//! Binary-cache retention, object-presence, and garbage-collection persistence.
//!
//! This module is the database boundary for RFC-0012's destructive cache
//! lifecycle. It deliberately separates four kinds of evidence:
//!
//! - logical cache objects and normalized closure edges;
//! - placement-scoped narinfo and NAR presence;
//! - provenance-bearing retention roots and immutable mark generations; and
//! - reviewed plans whose relational action manifests authorize deletion jobs.
//!
//! Every mutation that can change GC eligibility advances the cache epoch in
//! the same checked atomic batch as its domain rows. A zero-row compare-and-
//! swap is an error, not a successful no-op. Logical tombstones and physical
//! deletion jobs are separate: a failed or abandoned physical delete never
//! becomes confirmed reclaimed capacity.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};

use crate::backend::{CheckedStatement, Statement};
use crate::value::Row;

use super::{validate_key_bytes, Database, SurfaceObjectRecord};

/// Minimum interval between persisted access observations for one object.
const ACCESS_OBSERVATION_DEBOUNCE_SECS: i64 = 3_600;

/// One cache's concurrency fence for retention and garbage collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcStateRecord {
    /// Owning binary-cache database id.
    pub cache_id: i64,
    /// Single cache-wide mutation epoch.
    pub epoch: i64,
    /// Token of the mutation that most recently advanced `epoch`.
    pub epoch_owner_token: String,
    /// Root-set generation.
    pub root_generation: i64,
    /// Logical object-graph generation.
    pub object_graph_generation: i64,
    /// Last complete cache-wide placement inventory generation.
    pub inventory_generation: i64,
    /// Placement and policy topology generation.
    pub topology_generation: i64,
    /// Last complete immutable mark generation.
    pub current_mark_generation_id: Option<String>,
    /// Whether reviewed destructive apply is enabled.
    pub destructive_enabled: bool,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// Durable identity fence for one cache backend write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheWriteTicketRecord {
    /// Stable ticket echoed by multipart clients.
    pub ticket_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Placement-relative immutable object key.
    pub object_key: String,
    /// Client-declared final object size reserved against quota.
    pub declared_size: i64,
    /// Backend-observed final size after direct or multipart completion.
    pub observed_final_size: Option<i64>,
    /// Strong byte identity present at the target before admission.
    pub prior_object: Option<WriteObjectIdentity>,
    /// Expected SHA-256 of a proxied request body, when known.
    pub intended_object_hash: Option<String>,
    /// Multipart bytes durably admitted against the declaration.
    pub uploaded_size: i64,
    /// `single` or `multipart`.
    pub upload_kind: String,
    /// Exact selected placement.
    pub placement_id: i64,
    /// Placement version at authorization.
    pub placement_resource_version: i64,
    /// Placement write-spec version at authorization.
    pub placement_write_spec_version: i64,
    /// Exact binding.
    pub binding_id: i64,
    /// Mutable binding row version pinned by this write.
    pub binding_resource_version: i64,
    /// Immutable reconciled binding-write revision.
    pub binding_write_revision: i64,
    /// Credential purpose pinned by the revision.
    pub write_credential_purpose: String,
    /// Immutable credential generation.
    pub write_credential_generation: i64,
    /// Presign credential purpose for a direct-origin upload.
    pub presign_credential_purpose: Option<String>,
    /// Immutable presign credential generation for a direct-origin upload.
    pub presign_credential_generation: Option<i64>,
    /// Published inventory when the write began.
    pub starting_inventory_generation: i64,
    /// First complete inventory generation that covers the finished write.
    pub covered_inventory_generation: Option<i64>,
    /// Backend multipart identity, once attached.
    pub backend_upload_id: Option<String>,
    /// Ticket lifecycle.
    pub state: String,
    /// Exclusive completion deadline.
    pub expires_at: i64,
    /// Optimistic version.
    pub resource_version: i64,
}

/// One durable multipart-part admission owned by a write ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTicketPartRecord {
    /// One-based multipart part number.
    pub part_number: u32,
    /// Maximum bytes that may have reached the backend for this part identity.
    pub admitted_size: i64,
    /// Lowercase SHA-256 digest of the exact admitted request body.
    pub body_digest: String,
    /// `admitted`, `ambiguous`, or `confirmed`.
    pub state: String,
    /// Backend completion identity, present only after confirmed upload.
    pub etag: Option<String>,
}

/// Strong placement-scoped object identity captured at write admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteObjectIdentity {
    /// Exact object length.
    pub size: i64,
    /// Lowercase SHA-256 of the observed bytes.
    pub sha256: String,
    /// Backend-issued strong entity tag, when available.
    pub strong_etag: Option<String>,
}

/// One active logical Nix cache object projected from the normalized object graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheObjectRecord {
    /// Database identity used by graph and GC records.
    pub id: i64,
    /// Owning binary cache.
    pub cache_id: i64,
    /// Nix store-path hash.
    pub store_hash: String,
    /// Nix store-path basename.
    pub store_name: String,
    /// Logical narinfo surface object.
    pub narinfo_surface_object_id: i64,
    /// Logical shared-NAR surface object.
    pub nar_surface_object_id: i64,
    /// Placement-relative NAR key.
    pub nar_url: String,
    /// Uncompressed NAR hash.
    pub nar_hash: String,
    /// Uncompressed NAR size.
    pub nar_size: i64,
    /// Stored-file hash.
    pub file_hash: String,
    /// Stored-file size.
    pub file_size: i64,
    /// Compression encoding.
    pub compression: String,
    /// Optional derivation path.
    pub deriver: Option<String>,
    /// Sorted, deduplicated referenced store hashes.
    pub references: Vec<String>,
    /// Optional newline-separated signatures.
    pub signature: Option<String>,
    /// Optional content address.
    pub content_address: Option<String>,
    /// Publication time in Unix seconds.
    pub published_at: i64,
    /// Last observed access time.
    pub last_access_observed_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One cache-object tombstone that passed the bounded reaper preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapableCacheObjectTombstone {
    /// Owning binary cache.
    pub cache_id: i64,
    /// Tombstoned logical cache-object identity.
    pub cache_object_id: i64,
    /// Optimistic object version used by the reap mutation.
    pub resource_version: i64,
}

/// Aggregate logical usage for one binary cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheUsage {
    /// Sum of stored NAR file sizes across active logical objects.
    pub used_bytes: i64,
    /// Number of active logical objects.
    pub object_count: i64,
    /// Most recent active-object publication time, or zero for an empty cache.
    pub updated_at: i64,
}

/// Instance-wide binary-cache and garbage-collection metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheMetrics {
    /// Number of live binary caches.
    pub cache_count: i64,
    /// Number of active logical cache objects in live caches.
    pub object_count: i64,
    /// Stored bytes represented by active logical cache objects.
    pub used_bytes: i64,
    /// Number of successful cache-GC operations.
    pub gc_runs_ok: i64,
    /// Number of failed cache-GC operations.
    pub gc_runs_failed: i64,
    /// Bytes confirmed reclaimed by successful physical deletion jobs.
    pub gc_freed_bytes: i64,
}

/// Cache-global sweep mechanics, excluding registry retention selectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPolicyRecord {
    /// Owning cache.
    pub cache_id: i64,
    /// Minimum time an unrooted object remains protected.
    pub unreferenced_grace_secs: i64,
    /// Optional target capacity.
    pub soft_max_bytes: Option<i64>,
    /// Optional target object count.
    pub soft_max_objects: Option<i64>,
    /// Optional automatic planning interval.
    pub schedule_secs: Option<i64>,
    /// Maximum concurrent placement deletions.
    pub deletion_concurrency: i64,
    /// Initial retry delay.
    pub retry_initial_secs: i64,
    /// Maximum retry delay.
    pub retry_max_secs: i64,
    /// Maximum worker attempts.
    pub retry_max_attempts: i64,
    /// Minimum terminal tombstone retention.
    pub tombstone_retention_secs: i64,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// A registry-derived retention selector owned by one binary cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRetentionSubscriptionRecord {
    /// Database identity.
    pub id: i64,
    /// Cache protected by the selected registry artifacts.
    pub cache_id: i64,
    /// Registry supplying verified artifact provenance.
    pub registry_id: i64,
    /// Canonical typed selector document.
    pub selector_json: String,
    /// Digest of the exact canonical selector document.
    pub selector_digest: String,
    /// Grace interval for the replaced refresh generation.
    pub removal_grace_secs: i64,
    /// Explicit acknowledgement for public exposure, when required.
    pub exposure_acknowledged_at: Option<i64>,
    /// Whether new refreshes and the current generation are active.
    pub enabled: bool,
    /// Last registry revision activated successfully.
    pub last_successful_revision: Option<String>,
    /// Last terminal refresh time.
    pub last_refresh_at: Option<i64>,
    /// Current complete immutable refresh generation.
    pub current_refresh_id: Option<String>,
    /// `fresh`, `stale`, `refreshing`, or `failed`.
    pub refresh_state: String,
    /// Sanitized failure detail for the latest failed refresh.
    pub refresh_error: Option<String>,
    /// Logical retirement time.
    pub retired_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last configuration or refresh transition time.
    pub updated_at: i64,
}

/// Inputs for creating or replacing one cache retention subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCacheRetentionSubscriptionTopology {
    /// Destination cache.
    pub cache_id: i64,
    /// Artifact-source registry.
    pub registry_id: i64,
    /// Canonical typed selector document.
    pub selector_json: String,
    /// Digest of `selector_json`.
    pub selector_digest: String,
    /// Grace interval for replaced refresh generations.
    pub removal_grace_secs: i64,
    /// Explicit public-exposure acknowledgement time.
    pub exposure_acknowledged_at: Option<i64>,
    /// Whether refresh and root evaluation are enabled.
    pub enabled: bool,
    /// Expected subscription version, or `None` to create.
    pub expected_resource_version: Option<i64>,
    /// Expected cache mutation epoch.
    pub expected_cache_epoch: i64,
    /// Stable cache mutation token.
    pub mutation_id: String,
    /// Mutation time.
    pub now: i64,
}

/// A stable operator-created retention root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualRetentionRootRecord {
    /// Stable public root id.
    pub id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Root store hash.
    pub store_hash: String,
    /// `indefinite` or `leased`.
    pub protection_kind: String,
    /// Exact current lease head for a leased root.
    pub current_lease_id: Option<String>,
    /// Human reason.
    pub reason: String,
    /// Stable creating-principal kind.
    pub owner_kind: String,
    /// Stable creating-principal database identity.
    pub owner_id: i64,
    /// Creating principal.
    pub created_by: String,
    /// Creation time.
    pub created_at: i64,
    /// Logical deletion time.
    pub deleted_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// One immutable lease-history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionLeaseRecord {
    /// Stable lease id.
    pub id: String,
    /// Stable root id.
    pub manual_retention_root_id: String,
    /// Inclusive lease start.
    pub begins_at: i64,
    /// Exclusive lease end.
    pub expires_at: i64,
    /// Prior chain head.
    pub renewed_from_lease_id: Option<String>,
    /// `active`, `superseded`, or `revoked`.
    pub state: String,
    /// Principal that issued this generation.
    pub renewed_by: String,
    /// Issue time.
    pub renewed_at: i64,
    /// Revoking principal.
    pub revoked_by: Option<String>,
    /// Revocation time.
    pub revoked_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// One provenance-bearing reason that can seed a mark generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRootReasonRecord {
    /// Stable reason id.
    pub id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Supplying registry, when registry-derived.
    pub registry_id: Option<i64>,
    /// Root store hash.
    pub store_hash: String,
    /// Stable source-local reason identity.
    pub reason_key: String,
    /// `manual`, `lease`, `registry_catalog`, `release`, or `channel`.
    pub source_kind: String,
    /// Refresh generation, when registry-derived.
    pub refresh_id: Option<String>,
    /// Retention subscription, when registry-derived.
    pub retention_subscription_id: Option<i64>,
    /// Manual root, when operator-derived.
    pub manual_retention_root_id: Option<String>,
    /// Exact lease head, for a leased root.
    pub retention_lease_id: Option<String>,
    /// Verified release identity.
    pub release_id: Option<i64>,
    /// Complete immutable artifact snapshot.
    pub release_snapshot_id: Option<String>,
    /// Channel identity for partition reasons.
    pub channel_id: Option<i64>,
    /// Channel partition bucket.
    pub partition_bucket: Option<i64>,
    /// Source-specific human-readable reference.
    pub source_ref: String,
    /// Immutable source revision.
    pub source_revision: String,
    /// Optional reason expiry.
    pub expires_at: Option<i64>,
    /// Materialization time.
    pub refreshed_at: i64,
}

/// Input for an indefinite or lease-governed manual root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateManualRetentionRoot {
    /// Stable root identity.
    pub root_id: String,
    /// Stable reason-row identity.
    pub reason_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Store hash to protect.
    pub store_hash: String,
    /// Human reason.
    pub reason: String,
    /// Creating principal.
    pub actor: String,
    /// Stable creating-principal kind.
    pub actor_kind: String,
    /// Stable creating-principal database identity.
    pub actor_id: i64,
    /// Optional first lease id.
    pub lease_id: Option<String>,
    /// Optional exclusive lease end.
    pub lease_expires_at: Option<i64>,
    /// Expected cache epoch.
    pub expected_epoch: i64,
    /// Mutation token used as the new epoch owner.
    pub mutation_id: String,
    /// Mutation time and inclusive lease start.
    pub now: i64,
}

/// Input for an immutable successor lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewRetentionLease {
    /// Stable root id.
    pub root_id: String,
    /// Stable successor lease id.
    pub lease_id: String,
    /// Stable successor reason id.
    pub reason_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Expected root resource version.
    pub expected_root_version: i64,
    /// Exclusive successor expiry.
    pub expires_at: i64,
    /// Acting principal.
    pub actor: String,
    /// Expected cache epoch.
    pub expected_epoch: i64,
    /// Mutation token.
    pub mutation_id: String,
    /// Mutation time and inclusive lease start.
    pub now: i64,
}

/// Immutable inputs captured when a retention refresh begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginRetentionRefresh {
    /// Stable refresh id.
    pub refresh_id: String,
    /// Retention subscription database id.
    pub subscription_id: i64,
    /// Expected subscription resource version.
    pub expected_subscription_version: i64,
    /// Expected cache epoch.
    pub expected_cache_epoch: i64,
    /// Canonical selector digest.
    pub selector_digest: String,
    /// Exact indexed registry revision.
    pub registry_source_revision: String,
    /// Exact immutable registry-index generation.
    pub registry_index_generation: i64,
    /// Exact immutable registry-index content digest.
    pub registry_index_digest: String,
    /// Exact number of staged root reasons expected.
    pub expected_reason_count: i64,
    /// Refresh start time.
    pub started_at: i64,
}

/// One registry-derived reason staged under an unreachable refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionRefreshReason {
    /// Stable reason id.
    pub reason_id: String,
    /// Stable source-local identity.
    pub reason_key: String,
    /// Root store hash.
    pub store_hash: String,
    /// `registry_catalog`, `release`, or `channel`.
    pub source_kind: String,
    /// Verified release identity for release/channel reasons.
    pub release_id: Option<i64>,
    /// Complete immutable artifact snapshot for release/channel reasons.
    pub release_snapshot_id: Option<String>,
    /// Channel identity for channel reasons.
    pub channel_id: Option<i64>,
    /// Partition bucket for channel reasons.
    pub partition_bucket: Option<i64>,
    /// Source-specific human-readable reference.
    pub source_ref: String,
    /// Optional source-defined expiry.
    pub expires_at: Option<i64>,
    /// Materialization time.
    pub refreshed_at: i64,
}

/// One persisted placement-scoped deletion job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDeletionJobRecord {
    /// Stable job id.
    pub job_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Logical GC or eviction operation.
    pub operation_id: String,
    /// Physical object identity.
    pub surface_object_id: i64,
    /// Physical placement identity.
    pub placement_id: i64,
    /// `narinfo` or `nar` deletion phase.
    pub phase: String,
    /// Job lifecycle.
    pub state: String,
    /// Number of claimed attempts.
    pub attempt_count: i64,
    /// Maximum attempts before reviewed abandonment.
    pub max_attempts: i64,
    /// Earliest retry time.
    pub next_attempt_at: Option<i64>,
    /// Stable failure class.
    pub error_class: Option<String>,
    /// Sanitized failure detail.
    pub error: Option<String>,
    /// Bytes confirmed absent by a successful exact delete.
    pub confirmed_reclaimed_bytes: i64,
    /// Possible bytes deliberately abandoned.
    pub leaked_bytes: i64,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// Durable backend request and response evidence for one deletion attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDeletionAttemptReceipt {
    /// Stable idempotency key sent to the physical deletion controller.
    pub request_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Deletion job.
    pub job_id: String,
    /// One-based attempt number.
    pub attempt_number: i64,
    /// Exact physical placement.
    pub placement_id: i64,
    /// Exact physical object.
    pub surface_object_id: i64,
    /// Placement-relative backend key.
    pub object_key: String,
    /// Exact entity tag captured by the inventory.
    pub expected_etag: Option<String>,
    /// Exact content hash captured by the inventory.
    pub expected_hash: Option<String>,
    /// Exact byte size captured by the inventory.
    pub expected_size: Option<i64>,
    /// Complete inventory generation supplying the evidence.
    pub expected_inventory_generation: i64,
    /// Exact binding captured by inventory.
    pub binding_id: i64,
    /// Exact mutable binding row version/location.
    pub binding_resource_version: i64,
    /// Exact immutable delete credential generation.
    pub delete_credential_generation: i64,
    /// `requested`, `responded`, or `finalized`.
    pub state: String,
    /// Stable backend outcome, once responded.
    pub outcome: Option<String>,
    /// Entity tag returned by the backend, when any.
    pub response_etag: Option<String>,
    /// Content hash returned by the backend, when any.
    pub response_hash: Option<String>,
    /// Size returned by the backend, when any.
    pub response_size: Option<i64>,
    /// Stable failure class.
    pub error_class: Option<String>,
    /// Sanitized backend response detail.
    pub response_detail: Option<String>,
    /// Time the durable request was created.
    pub requested_at: i64,
    /// Time the durable response was recorded.
    pub responded_at: Option<i64>,
    /// Time the response was applied to the job.
    pub finalized_at: Option<i64>,
}

/// Exact response persisted before a deletion job can become terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordObjectDeletionAttemptResponse {
    /// Stable request identity.
    pub request_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Deletion job.
    pub job_id: String,
    /// Backend outcome.
    pub outcome: String,
    /// Entity tag returned by the backend, when any.
    pub response_etag: Option<String>,
    /// Hash returned by the backend, when any.
    pub response_hash: Option<String>,
    /// Size returned by the backend, when any.
    pub response_size: Option<i64>,
    /// Stable failure class for failed outcomes.
    pub error_class: Option<String>,
    /// Sanitized failure detail for failed outcomes.
    pub response_detail: Option<String>,
    /// Backend response time.
    pub responded_at: i64,
}

/// Inputs that must exactly match an immutable GC plan at apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyCacheGcPlan {
    /// Stable reviewed plan id.
    pub plan_id: String,
    /// Stable claim/epoch-owner token.
    pub claim_id: String,
    /// Deterministic resulting operation id.
    pub operation_id: String,
    /// Exact actor and scope digest from the plan.
    pub actor_scope_digest: String,
    /// Exact confirmation hash shown during review.
    pub confirmation_hash: String,
    /// Apply time.
    pub now: i64,
}

/// A complete normalized logical cache object ready for activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateCacheObject {
    /// Client-assigned database identity.
    pub object_id: i64,
    /// Owning cache.
    pub cache_id: i64,
    /// Store-path hash.
    pub store_hash: String,
    /// Store-path name.
    pub store_name: String,
    /// Distinct `<store-hash>.narinfo` surface object.
    pub narinfo_surface_object_id: i64,
    /// Shared NAR surface object.
    pub nar_surface_object_id: i64,
    /// Uncompressed NAR hash.
    pub nar_hash: String,
    /// Uncompressed NAR size.
    pub nar_size: i64,
    /// Stored file hash.
    pub file_hash: String,
    /// Stored file size.
    pub file_size: i64,
    /// Compression encoding.
    pub compression: String,
    /// Optional deriver.
    pub deriver: Option<String>,
    /// Optional signature.
    pub signature: Option<String>,
    /// Optional content address.
    pub content_address: Option<String>,
    /// Normalized referenced store hashes.
    pub references: Vec<String>,
    /// Active upload/population/replication/repair operation fencing the hash.
    pub mutation_fence_operation_id: String,
    /// Expected active-fence resource version.
    pub expected_fence_version: i64,
    /// Expected cache epoch.
    pub expected_epoch: i64,
    /// Mutation/epoch-owner token.
    pub mutation_id: String,
    /// Publication time.
    pub published_at: i64,
}

/// One placement observation staged into a cache inventory generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheObjectPresenceObservation {
    /// Owning cache.
    pub cache_id: i64,
    /// Surface-relative object key staged for this placement and generation.
    pub object_key: String,
    /// Cache placement.
    pub placement_id: i64,
    /// `present`, `copying`, `missing`, `corrupt`, or `deleting`.
    pub state: String,
    /// Observed content hash.
    pub observed_hash: Option<String>,
    /// Observed bytes.
    pub observed_size: Option<i64>,
    /// Origin version token.
    pub etag: Option<String>,
    /// Building cache-wide inventory generation.
    pub inventory_generation: i64,
    /// Observation time.
    pub observed_at: i64,
}

/// One provider listing identity staged without retaining object bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheInventoryListedObject {
    /// Surface-relative object key.
    pub object_key: String,
    /// Lowercase hexadecimal SHA-256 derived or safely reused for the bytes.
    pub observed_sha256: String,
    /// Observed representation size.
    pub observed_size: i64,
    /// Provider-issued strong version identifier, when available.
    pub etag: Option<String>,
}

/// Maximum listing identities persisted by one inventory transaction.
pub const MAX_CACHE_INVENTORY_LISTED_OBJECT_BATCH: usize = 256;

/// Normalized narinfo metadata staged under one unpublished inventory generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheInventoryNarinfoCandidate {
    /// Owning cache.
    pub cache_id: i64,
    /// Unpublished inventory generation.
    pub generation: i64,
    /// Placement that supplied matching narinfo and NAR evidence.
    pub placement_id: i64,
    /// Nix store-path hash.
    pub store_hash: String,
    /// Nix store-path basename.
    pub store_name: String,
    /// Digest of all normalized immutable metadata.
    pub identity_digest: String,
    /// Staged narinfo object key.
    pub narinfo_object_key: String,
    /// Staged NAR object key.
    pub nar_object_key: String,
    /// Uncompressed NAR hash.
    pub nar_hash: String,
    /// Uncompressed NAR size.
    pub nar_size: i64,
    /// Stored-file hash.
    pub file_hash: String,
    /// Stored-file size.
    pub file_size: i64,
    /// Compression encoding.
    pub compression: String,
    /// Optional derivation path.
    pub deriver: Option<String>,
    /// Optional signatures.
    pub signature: Option<String>,
    /// Optional content address.
    pub content_address: Option<String>,
    /// Sorted, deduplicated referenced store hashes.
    pub references: Vec<String>,
    /// Observation time.
    pub published_at: i64,
}

/// Captured inputs for an immutable closure-mark generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginCacheGcGeneration {
    /// Stable generation id.
    pub generation_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Wall-clock cutoff used for leases, grace, and eligibility.
    pub cutoff_at: i64,
    /// Expected cache epoch.
    pub expected_epoch: i64,
    /// Generation creation time.
    pub created_at: i64,
}

/// One explicit mark coverage failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcCoverageError {
    /// Stable error id.
    pub error_id: String,
    /// `missing_root`, `missing_reference`, or `stale_inventory`.
    pub kind: String,
    /// Missing root or source object.
    pub store_hash: Option<String>,
    /// Missing referenced object.
    pub referenced_store_hash: Option<String>,
    /// Human-readable diagnostic.
    pub detail: String,
}

/// One logical candidate in an immutable reviewed GC plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanObjectInput {
    /// Cache-object database id.
    pub cache_object_id: i64,
    /// Immutable store-path hash snapshot.
    pub store_hash: String,
    /// Exact resource version.
    pub expected_object_version: i64,
    /// Exact first-unreferenced time.
    pub expected_unreferenced_since: i64,
    /// `ttl`, `byte_cap`, or `object_cap`.
    pub eligibility_reason: String,
    /// Logical file bytes used in the plan summary.
    pub logical_bytes: i64,
}

/// One exact placement-scoped physical action in a GC plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanActionInput {
    /// Stable action id; also the default deletion-job id.
    pub action_id: String,
    /// Narinfo or shared-NAR surface object.
    pub surface_object_id: i64,
    /// Exact placement.
    pub placement_id: i64,
    /// `narinfo` or `nar`.
    pub phase: String,
    /// Exact origin version token.
    pub expected_etag: Option<String>,
    /// Exact observed hash.
    pub expected_hash: Option<String>,
    /// Exact observed bytes.
    pub expected_size: Option<i64>,
    /// Complete inventory generation supplying the evidence.
    pub expected_inventory_generation: i64,
    /// Exact binding selected by inventory.
    pub binding_id: i64,
    /// Exact binding row version selected by inventory.
    pub binding_resource_version: i64,
    /// Validated delete credential generation reviewed by the plan.
    pub delete_credential_generation: i64,
    /// Estimated unique reclaimable bytes.
    pub estimated_reclaimable_bytes: i64,
}

/// Relates a logical candidate to one shared physical action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanObjectActionInput {
    /// Candidate cache-object id.
    pub cache_object_id: i64,
    /// Physical action id.
    pub action_id: String,
}

/// Orders a shared NAR delete after an exact narinfo delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcActionDependencyInput {
    /// Dependent NAR action.
    pub action_id: String,
    /// Prerequisite narinfo action.
    pub prerequisite_action_id: String,
}

/// Complete immutable relational GC plan manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCacheGcPlan {
    /// Stable reviewed plan id.
    pub plan_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Complete mark generation.
    pub generation_id: String,
    /// Expected cache epoch.
    pub expected_epoch: i64,
    /// Digest of every captured input version.
    pub input_versions_digest: String,
    /// Digest of the ordered relational manifest.
    pub manifest_digest: String,
    /// Exact actor/scope authorization digest.
    pub actor_scope_digest: String,
    /// User-visible confirmation hash.
    pub confirmation_hash: String,
    /// Creating principal.
    pub created_by: String,
    /// Caller-supplied retry identity for plan creation.
    pub request_idempotency_key: String,
    /// Canonical request digest used to reject key reuse.
    pub request_digest: String,
    /// Creation time.
    pub created_at: i64,
    /// Expiration time.
    pub expires_at: i64,
    /// Ordered logical candidates.
    pub objects: Vec<CacheGcPlanObjectInput>,
    /// Ordered unique physical actions.
    pub actions: Vec<CacheGcPlanActionInput>,
    /// Candidate/action fan-out.
    pub object_actions: Vec<CacheGcPlanObjectActionInput>,
    /// Narinfo-before-NAR dependencies.
    pub dependencies: Vec<CacheGcActionDependencyInput>,
}

/// A complete GC plan projection for API and controller reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanView {
    /// Stable plan identity.
    pub plan_id: String,
    /// Owning cache.
    pub cache_id: i64,
    /// Source mark generation.
    pub generation_id: String,
    /// Captured cache epoch.
    pub expected_epoch: i64,
    /// Captured policy version.
    pub policy_version: i64,
    /// Captured root-set version.
    pub root_generation: i64,
    /// Captured object-graph version.
    pub object_graph_generation: i64,
    /// Captured topology version.
    pub topology_generation: i64,
    /// Candidate manifest digest.
    pub manifest_digest: String,
    /// Review confirmation hash.
    pub confirmation_hash: String,
    /// Plan expiry.
    pub expires_at: i64,
    /// Logical candidates.
    pub objects: Vec<CacheGcPlanObjectView>,
    /// Physical actions, repeated for every associated store object.
    pub actions: Vec<CacheGcPlanActionView>,
}

/// One logical candidate in a persisted GC plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanObjectView {
    /// Cache-object identity.
    pub cache_object_id: i64,
    /// Store-path hash.
    pub store_hash: String,
    /// Planned logical bytes.
    pub logical_bytes: i64,
    /// Eligibility class.
    pub eligibility_reason: String,
}

/// One placement action associated with one plan candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGcPlanActionView {
    /// Stable action identity.
    pub action_id: String,
    /// Associated store-path hash.
    pub store_hash: String,
    /// Physical placement identity.
    pub placement_id: i64,
    /// `narinfo` or `nar`.
    pub phase: String,
    /// Captured inventory generation.
    pub inventory_generation: i64,
}

fn validate_stable_key(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 || value.bytes().any(|b| b.is_ascii_control()) {
        bail!("{label} must contain 1 through 64 non-control UTF-8 bytes");
    }
    Ok(())
}

fn validate_store_hash(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        bail!("store hash must be 1 through 64 lowercase ASCII alphanumeric bytes");
    }
    Ok(())
}

fn validate_gc_policy(policy: &CacheGcPolicyRecord) -> Result<()> {
    if policy.cache_id <= 0
        || policy.unreferenced_grace_secs < 0
        || policy.soft_max_bytes.is_some_and(|value| value < 0)
        || policy.soft_max_objects.is_some_and(|value| value < 0)
        || policy.schedule_secs.is_some_and(|value| value <= 0)
        || policy.deletion_concurrency <= 0
        || policy.retry_initial_secs <= 0
        || policy.retry_max_secs < policy.retry_initial_secs
        || policy.retry_max_attempts <= 0
        || policy.tombstone_retention_secs < 0
    {
        bail!("cache GC policy values are outside their valid ranges");
    }
    Ok(())
}

fn digest_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn cache_gc_manifest_digest(input: &CreateCacheGcPlan) -> Result<String> {
    let objects = input
        .objects
        .iter()
        .map(|object| {
            serde_json::json!({
                "cache_object_id": object.cache_object_id,
                "store_hash": object.store_hash,
                "expected_object_version": object.expected_object_version,
                "expected_unreferenced_since": object.expected_unreferenced_since,
                "eligibility_reason": object.eligibility_reason,
                "logical_bytes": object.logical_bytes,
            })
        })
        .collect::<Vec<_>>();
    let actions = input
        .actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "action_id": action.action_id,
                "surface_object_id": action.surface_object_id,
                "placement_id": action.placement_id,
                "phase": action.phase,
                "expected_etag": action.expected_etag,
                "expected_hash": action.expected_hash,
                "expected_size": action.expected_size,
                "expected_inventory_generation": action.expected_inventory_generation,
                "binding_id": action.binding_id,
                "binding_resource_version": action.binding_resource_version,
                "delete_credential_generation": action.delete_credential_generation,
                "estimated_reclaimable_bytes": action.estimated_reclaimable_bytes,
            })
        })
        .collect::<Vec<_>>();
    let object_actions = input
        .object_actions
        .iter()
        .map(|link| serde_json::json!([link.cache_object_id, link.action_id]))
        .collect::<Vec<_>>();
    let dependencies = input
        .dependencies
        .iter()
        .map(|dependency| {
            serde_json::json!([dependency.action_id, dependency.prerequisite_action_id])
        })
        .collect::<Vec<_>>();
    Ok(digest_text(&serde_json::to_string(&serde_json::json!({
        "objects": objects,
        "actions": actions,
        "object_actions": object_actions,
        "dependencies": dependencies,
    }))?))
}

impl Database {
    /// Initializes the fail-closed GC state for a newly-created empty cache.
    ///
    /// The first published inventory is the canonical empty inventory. No
    /// destructive work is enabled until the separately reviewed first sweep
    /// acknowledgement advances the cache epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache is missing, already initialized, or the
    /// atomic initialization batch cannot be persisted.
    pub async fn initialize_new_cache_gc_topology(
        &self,
        cache_id: i64,
        created_at: i64,
    ) -> Result<()> {
        if cache_id <= 0 {
            bail!("cache GC initialization requires a positive cache id");
        }
        let epoch_owner_token = uuid::Uuid::new_v4().simple().to_string();
        let empty_inventory_digest = hex::encode(Sha256::digest([]));
        let statements = vec![
            Statement::new(
                "INSERT INTO cache_inventory_generations
                 (cache_id, generation, owner_token, lease_expires_at,
                  state, content_digest, published_at, created_at)
                 SELECT id, 1, ?4, ?3 + 1, 'published', ?2, ?3, ?3
                 FROM binary_caches WHERE id = ?1",
                vals![
                    cache_id,
                    empty_inventory_digest,
                    created_at,
                    epoch_owner_token
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_policies
                 (cache_id, unreferenced_grace_secs, soft_max_bytes,
                  soft_max_objects, schedule_secs, deletion_concurrency,
                  retry_initial_secs, retry_max_secs, retry_max_attempts,
                  tombstone_retention_secs, resource_version)
                 VALUES (?1, 604800, NULL, NULL, 86400, 4, 60, 3600, 10,
                         2592000, 1)",
                vals![cache_id],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_state
                 (cache_id, epoch, epoch_owner_token, root_generation,
                  object_graph_generation, inventory_generation,
                  topology_generation, destructive_enabled, resource_version)
                 VALUES (?1, 0, ?2, 0, 0, 1, 0, 0, 1)",
                vals![cache_id, epoch_owner_token],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_deletion_capacity (cache_id, running_count)
                 VALUES (?1, 0)",
                vals![cache_id],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_heads (cache_id, resource_version, updated_at)
                 VALUES (?1, 1, ?2)",
                vals![cache_id, created_at],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Discards an unpublished cache inventory so its generation can retry.
    ///
    /// Deleting the generation cascades every staged identity and observation;
    /// published inventory is never changed by this recovery path.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity or a database failure.
    pub async fn fail_cache_inventory_topology(
        &self,
        cache_id: i64,
        generation: i64,
        owner_token: &str,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if cache_id <= 0 || generation <= 0 {
            bail!("cache inventory failure identity is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "DELETE FROM cache_inventory_generations
                     WHERE cache_id = ?1 AND generation = ?2
                       AND owner_token = ?3 AND state = 'building'",
                vals![cache_id, generation, owner_token],
            )
            .unchecked()])
            .await
    }

    /// Creates one durable cache-write fence pinned to reconciled physical identity.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, invalid identity, another active
    /// cache write, an unvalidated credential, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_cache_write_ticket(
        &self,
        ticket_id: &str,
        cache_id: i64,
        placement_id: i64,
        expected_placement_resource_version: i64,
        expected_binding_write_revision: i64,
        expected_write_credential_generation: i64,
        object_key: &str,
        declared_size: i64,
        upload_kind: &str,
        quota_org_id: Option<i64>,
        quota_delta_bytes: i64,
        quota_delta_objects: i64,
        expires_at: i64,
        now: i64,
        prior_object: Option<&WriteObjectIdentity>,
        intended_object_hash: Option<&str>,
    ) -> Result<CacheWriteTicketRecord> {
        validate_stable_key(ticket_id, "cache write ticket id")?;
        if prior_object.is_some() || intended_object_hash.is_some() {
            bail!("observing cache ticket cannot carry baseline identity");
        }
        if cache_id <= 0
            || placement_id <= 0
            || expected_placement_resource_version <= 0
            || expected_binding_write_revision <= 0
            || expected_write_credential_generation <= 0
            || object_key.is_empty()
            || declared_size < 0
            || !matches!(upload_kind, "single" | "multipart")
            || quota_delta_bytes != 0
            || quota_delta_objects != 0
            || (quota_org_id.is_none() && (quota_delta_bytes != 0 || quota_delta_objects != 0))
            || expires_at <= now
        {
            bail!("cache write ticket input is invalid");
        }
        let statements = vec![Statement::new(
            "INSERT INTO cache_write_tickets
                 (ticket_id, cache_id, object_key, declared_size, upload_kind, placement_id,
                  prior_object_size, prior_object_hash, prior_object_etag, intended_object_hash,
                  placement_resource_version, placement_write_spec_version,
                  binding_id, binding_resource_version,
                  binding_write_revision, write_credential_purpose,
                  write_credential_generation, starting_inventory_generation,
                  quota_org_id, quota_delta_bytes, quota_delta_objects, quota_state,
                  state, active_cache_slot, expires_at, created_at)
                 SELECT ?1, ?2, ?4, ?11, ?5, placement.id, ?12, ?13, ?14, ?15,
                        placement.resource_version, placement.write_spec_version,
                        binding.id, binding.resource_version, revision.revision,
                        revision.write_credential_purpose,
                        revision.write_credential_generation,
                        state.inventory_generation, ?6, ?7, ?8,
                        CASE WHEN ?6 IS NULL THEN 'none' ELSE 'pending' END,
                        'observing', 1, ?9, ?10
                 FROM surface_placement_effective placement
                 JOIN bindings binding
                   ON binding.id = placement.binding_id
                 JOIN binding_write_revisions revision
                   ON revision.binding_id = binding.id
                  AND revision.revision = placement.authority_observed_binding_write_revision
                 JOIN binding_credential_revisions credential
                   ON credential.binding_id = revision.binding_id
                  AND credential.purpose = revision.write_credential_purpose
                  AND credential.generation = revision.write_credential_generation
                 JOIN cache_gc_state state ON state.cache_id = placement.cache_id
                 WHERE placement.id = ?3 AND placement.cache_id = ?2
                   AND placement.resource_version = ?16
                   AND revision.revision = ?17
                   AND revision.write_credential_generation = ?18
                   AND placement.effective_write_enabled = 1
                   AND credential.validation_state = 'valid'
                   AND EXISTS (SELECT 1 FROM binary_caches owner
                     LEFT JOIN orgs org ON org.id = owner.org_id
                     WHERE owner.id = ?2
                       AND (owner.org_id IS NULL OR org.deleted_at IS NULL)
                       AND (owner.org_id = ?6
                         OR (owner.org_id IS NULL AND ?6 IS NULL)))
                   AND NOT EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                     WHERE inventory.cache_id = ?2 AND inventory.state = 'building')
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     JOIN surface_objects object
                       ON object.id = job.surface_object_id
                      AND object.cache_id = job.cache_id
                     WHERE job.cache_id = ?2 AND job.active_slot = 1
                       AND object.object_key = ?4)",
            vals![
                ticket_id,
                cache_id,
                placement_id,
                object_key,
                upload_kind,
                quota_org_id,
                quota_delta_bytes,
                quota_delta_objects,
                expires_at,
                now,
                declared_size,
                prior_object.map(|identity| identity.size),
                prior_object.map(|identity| identity.sha256.as_str()),
                prior_object.and_then(|identity| identity.strong_etag.as_deref()),
                intended_object_hash,
                expected_placement_resource_version,
                expected_binding_write_revision,
                expected_write_credential_generation
            ],
        )
        .expecting(1)];
        self.backend.checked_batch(&statements).await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("created cache write ticket disappeared")
    }

    /// Activates an observing cache-write fence after capturing its baseline.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence or quota, stale observation state,
    /// quota exhaustion, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_cache_write_ticket(
        &self,
        ticket_id: &str,
        expected_version: i64,
        quota_org_id: Option<i64>,
        quota_delta_bytes: i64,
        quota_delta_objects: i64,
        prior_object: Option<&WriteObjectIdentity>,
        intended_object_hash: Option<&str>,
        now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        validate_write_identities(prior_object, intended_object_hash)?;
        if quota_delta_objects < 0
            || (quota_org_id.is_none() && (quota_delta_bytes != 0 || quota_delta_objects != 0))
        {
            bail!("cache write activation quota is invalid");
        }
        let mut statements =
            quota_reservation_statements(quota_org_id, quota_delta_bytes, quota_delta_objects, now);
        statements.push(
            Statement::new(
                "UPDATE cache_write_tickets
             SET prior_object_size = ?6, prior_object_hash = ?7,
                 prior_object_etag = ?8, intended_object_hash = ?9,
                 quota_delta_bytes = ?4, quota_delta_objects = ?5,
                 quota_state = CASE WHEN ?3 IS NULL THEN 'none' ELSE 'reserved' END,
                 state = 'active', resource_version = resource_version + 1
             WHERE ticket_id = ?1 AND resource_version = ?2
               AND state = 'observing' AND active_cache_slot = 1
               AND (quota_org_id = ?3 OR (quota_org_id IS NULL AND ?3 IS NULL))
               AND expires_at > ?10
               AND EXISTS (SELECT 1 FROM surface_placement_effective placement
                 JOIN bindings binding
                   ON binding.id = placement.binding_id
                 JOIN binding_credential_revisions credential
                   ON credential.binding_id = binding.id
                  AND credential.purpose = cache_write_tickets.write_credential_purpose
                  AND credential.generation = cache_write_tickets.write_credential_generation
                 JOIN cache_gc_state cache_state
                   ON cache_state.cache_id = cache_write_tickets.cache_id
                 WHERE placement.id = cache_write_tickets.placement_id
                   AND placement.cache_id = cache_write_tickets.cache_id
                   AND placement.resource_version
                     = cache_write_tickets.placement_resource_version
                   AND placement.write_spec_version
                     = cache_write_tickets.placement_write_spec_version
                   AND placement.binding_id
                     = cache_write_tickets.binding_id
                   AND placement.authority_observed_binding_write_revision
                     = cache_write_tickets.binding_write_revision
                   AND placement.effective_write_enabled = 1
                   AND binding.resource_version
                     = cache_write_tickets.binding_resource_version
                   AND credential.validation_state = 'valid'
                   AND cache_state.inventory_generation
                     = cache_write_tickets.starting_inventory_generation)",
                vals![
                    ticket_id,
                    expected_version,
                    quota_org_id,
                    quota_delta_bytes,
                    quota_delta_objects,
                    prior_object.map(|identity| identity.size),
                    prior_object.map(|identity| identity.sha256.as_str()),
                    prior_object.and_then(|identity| identity.strong_etag.as_deref()),
                    intended_object_hash,
                    now
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("activated cache write ticket disappeared")
    }

    /// Creates a durable direct-origin PUT fence with exact write and presign pins.
    ///
    /// # Errors
    ///
    /// Returns an error for stale authority, an invalid presign credential,
    /// inventory/deletion overlap, another same-key write, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_presigned_cache_write_ticket(
        &self,
        ticket_id: &str,
        cache_id: i64,
        placement_id: i64,
        expected_placement_resource_version: i64,
        expected_binding_write_revision: i64,
        expected_write_credential_generation: i64,
        object_key: &str,
        declared_size: i64,
        quota_org_id: Option<i64>,
        quota_delta_bytes: i64,
        quota_delta_objects: i64,
        expires_at: i64,
        now: i64,
        prior_object: Option<&WriteObjectIdentity>,
        intended_object_hash: Option<&str>,
    ) -> Result<CacheWriteTicketRecord> {
        validate_stable_key(ticket_id, "cache write ticket id")?;
        if prior_object.is_some() || intended_object_hash.is_some() {
            bail!("observing presigned ticket cannot carry baseline identity");
        }
        if cache_id <= 0
            || placement_id <= 0
            || expected_placement_resource_version <= 0
            || expected_binding_write_revision <= 0
            || expected_write_credential_generation <= 0
            || object_key.is_empty()
            || declared_size < 0
            || quota_delta_bytes != 0
            || quota_delta_objects != 0
            || (quota_org_id.is_none() && (quota_delta_bytes != 0 || quota_delta_objects != 0))
            || expires_at <= now
        {
            bail!("presigned cache write ticket input is invalid");
        }
        let statements = vec![Statement::new(
            "INSERT INTO cache_write_tickets
             (ticket_id, cache_id, object_key, declared_size, upload_kind, placement_id,
              prior_object_size, prior_object_hash, prior_object_etag, intended_object_hash,
              placement_resource_version, placement_write_spec_version,
              binding_id, binding_resource_version, binding_write_revision,
              write_credential_purpose, write_credential_generation,
              presign_credential_purpose, presign_credential_generation,
              starting_inventory_generation, quota_org_id, quota_delta_bytes,
              quota_delta_objects, quota_state, state, active_cache_slot,
              expires_at, created_at)
             SELECT ?1, ?2, ?4, ?10, 'presigned', placement.id, ?11, ?12, ?13, ?14,
                    placement.resource_version, placement.write_spec_version,
                    binding.id, binding.resource_version, revision.revision,
                    revision.write_credential_purpose,
                    revision.write_credential_generation,
                    'presign', presign.generation, state.inventory_generation,
                    ?5, ?6, ?7, CASE WHEN ?5 IS NULL THEN 'none' ELSE 'pending' END,
                    'observing', 1, ?8, ?9
             FROM surface_placement_effective placement
             JOIN bindings binding ON binding.id = placement.binding_id
             JOIN binding_write_revisions revision
               ON revision.binding_id = binding.id
              AND revision.revision = placement.authority_observed_binding_write_revision
             JOIN binding_credential_revisions write_credential
               ON write_credential.binding_id = revision.binding_id
              AND write_credential.purpose = revision.write_credential_purpose
              AND write_credential.generation = revision.write_credential_generation
             JOIN binding_credential_heads presign_head
               ON presign_head.binding_id = binding.id
              AND presign_head.purpose = 'presign'
             JOIN binding_credential_revisions presign
               ON presign.binding_id = presign_head.binding_id
              AND presign.purpose = presign_head.purpose
              AND presign.generation = presign_head.current_generation
             JOIN cache_gc_state state ON state.cache_id = placement.cache_id
             WHERE placement.id = ?3 AND placement.cache_id = ?2
               AND placement.resource_version = ?15
               AND revision.revision = ?16
               AND revision.write_credential_generation = ?17
               AND placement.effective_write_enabled = 1
               AND binding.kind IN ('s3', 'r2') AND binding.access_mode = 'private'
               AND write_credential.validation_state = 'valid'
               AND presign.validation_state = 'valid'
               AND EXISTS (SELECT 1 FROM binary_caches owner
                 LEFT JOIN orgs org ON org.id = owner.org_id
                 WHERE owner.id = ?2
                   AND (owner.org_id IS NULL OR org.deleted_at IS NULL)
                   AND (owner.org_id = ?5
                     OR (owner.org_id IS NULL AND ?5 IS NULL)))
               AND NOT EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                 WHERE inventory.cache_id = ?2 AND inventory.state = 'building')
               AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                 JOIN surface_objects object ON object.id = job.surface_object_id
                   AND object.cache_id = job.cache_id
                 WHERE job.cache_id = ?2 AND job.active_slot = 1
                   AND object.object_key = ?4)",
            vals![
                ticket_id,
                cache_id,
                placement_id,
                object_key,
                quota_org_id,
                quota_delta_bytes,
                quota_delta_objects,
                expires_at,
                now,
                declared_size,
                prior_object.map(|identity| identity.size),
                prior_object.map(|identity| identity.sha256.as_str()),
                prior_object.and_then(|identity| identity.strong_etag.as_deref()),
                intended_object_hash,
                expected_placement_resource_version,
                expected_binding_write_revision,
                expected_write_credential_generation
            ],
        )
        .expecting(1)];
        self.backend.checked_batch(&statements).await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("created presigned cache write ticket disappeared")
    }

    /// Returns one durable cache-write ticket.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed data.
    pub async fn cache_write_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<Option<CacheWriteTicketRecord>> {
        validate_stable_key(ticket_id, "cache write ticket id")?;
        self.backend
            .query_opt(
                "SELECT ticket_id, cache_id, object_key, declared_size, observed_final_size, uploaded_size, upload_kind,
                        placement_id, placement_resource_version,
                        placement_write_spec_version, binding_id,
                        binding_resource_version, binding_write_revision,
                        write_credential_purpose, write_credential_generation,
                        presign_credential_purpose, presign_credential_generation,
                        starting_inventory_generation, covered_inventory_generation,
                        backend_upload_id,
                        state, expires_at, resource_version,
                        prior_object_size, prior_object_hash, prior_object_etag,
                        intended_object_hash
                 FROM cache_write_tickets WHERE ticket_id = ?1",
                &vals![ticket_id],
            )
            .await?
            .map(|row| row_to_cache_write_ticket(&row))
            .transpose()
    }

    /// Returns an active write ticket that is safe to hand back to a retrying client.
    ///
    /// The lookup pins the complete reconciled writer identity in addition to
    /// the request identity. An old ticket therefore cannot cross a placement,
    /// binding, credential, inventory, or authority transition merely because
    /// its object key still matches.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lifecycle state, database failure, or
    /// malformed persisted data.
    #[allow(clippy::too_many_arguments)]
    pub async fn reusable_cache_write_ticket(
        &self,
        cache_id: i64,
        object_key: &str,
        declared_size: i64,
        upload_kind: &str,
        state: &str,
        intended_object_hash: Option<&str>,
        placement_id: i64,
        expected_placement_resource_version: i64,
        expected_binding_write_revision: i64,
        expected_write_credential_generation: i64,
        now: i64,
    ) -> Result<Option<CacheWriteTicketRecord>> {
        if !matches!(
            (upload_kind, state),
            ("single", "observing")
                | ("single", "active")
                | ("multipart", "observing" | "active" | "completing")
        ) {
            bail!("reusable cache write ticket lifecycle is invalid");
        }
        self.backend
            .query_opt(
                "SELECT ticket.ticket_id, ticket.cache_id, ticket.object_key,
                        ticket.declared_size, ticket.observed_final_size,
                        ticket.uploaded_size, ticket.upload_kind,
                        ticket.placement_id, ticket.placement_resource_version,
                        ticket.placement_write_spec_version, ticket.binding_id,
                        ticket.binding_resource_version, ticket.binding_write_revision,
                        ticket.write_credential_purpose,
                        ticket.write_credential_generation,
                        ticket.presign_credential_purpose,
                        ticket.presign_credential_generation,
                        ticket.starting_inventory_generation,
                        ticket.covered_inventory_generation, ticket.backend_upload_id,
                        ticket.state, ticket.expires_at, ticket.resource_version,
                        ticket.prior_object_size, ticket.prior_object_hash,
                        ticket.prior_object_etag, ticket.intended_object_hash
                 FROM cache_write_tickets ticket
                 JOIN surface_placement_effective placement
                   ON placement.id = ticket.placement_id
                  AND placement.cache_id = ticket.cache_id
                 JOIN bindings binding
                   ON binding.id = ticket.binding_id
                 JOIN binding_credential_revisions credential
                   ON credential.binding_id = ticket.binding_id
                  AND credential.purpose = ticket.write_credential_purpose
                  AND credential.generation = ticket.write_credential_generation
                 JOIN cache_gc_state cache_state ON cache_state.cache_id = ticket.cache_id
                 WHERE ticket.cache_id = ?1 AND ticket.object_key = ?2
                   AND ticket.declared_size = ?3 AND ticket.upload_kind = ?4
                   AND ticket.state = ?5 AND ticket.active_cache_slot = 1
                   AND ticket.expires_at > ?6
                   AND ((ticket.intended_object_hash = ?7)
                     OR (ticket.intended_object_hash IS NULL AND ?7 IS NULL)
                     OR (?4 = 'single' AND ?5 = 'active' AND ?7 IS NULL
                       AND ticket.intended_object_hash IS NOT NULL))
                   AND ticket.placement_id = ?8
                   AND ticket.placement_resource_version = ?9
                   AND placement.resource_version = ticket.placement_resource_version
                   AND placement.write_spec_version = ticket.placement_write_spec_version
                   AND placement.binding_id = ticket.binding_id
                   AND placement.authority_observed_binding_write_revision
                     = ticket.binding_write_revision
                   AND ticket.binding_write_revision = ?10
                   AND ticket.write_credential_generation = ?11
                   AND placement.effective_write_enabled = 1
                   AND binding.resource_version = ticket.binding_resource_version
                   AND credential.validation_state = 'valid'
                   AND cache_state.inventory_generation
                     = ticket.starting_inventory_generation
                   AND (?5 <> 'completing' OR ticket.backend_upload_id IS NOT NULL)",
                &vals![
                    cache_id,
                    object_key,
                    declared_size,
                    upload_kind,
                    state,
                    now,
                    intended_object_hash,
                    placement_id,
                    expected_placement_resource_version,
                    expected_binding_write_revision,
                    expected_write_credential_generation
                ],
            )
            .await?
            .map(|row| row_to_cache_write_ticket(&row))
            .transpose()
    }

    /// Lists expired active write tickets for durable backend recovery.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_expired_cache_write_tickets(
        &self,
        cache_id: i64,
        now: i64,
        after_expires_at: i64,
        after_ticket_id: &str,
        limit: i64,
    ) -> Result<Vec<CacheWriteTicketRecord>> {
        if !(1..=256).contains(&limit) {
            bail!("expired cache write ticket page limit must be between 1 and 256");
        }
        self.backend
            .query(
                "SELECT ticket_id, cache_id, object_key, declared_size, observed_final_size, uploaded_size, upload_kind,
                        placement_id, placement_resource_version,
                        placement_write_spec_version, binding_id,
                        binding_resource_version, binding_write_revision,
                        write_credential_purpose, write_credential_generation,
                        presign_credential_purpose, presign_credential_generation,
                        starting_inventory_generation, covered_inventory_generation,
                        backend_upload_id, state, expires_at, resource_version,
                        prior_object_size, prior_object_hash, prior_object_etag,
                        intended_object_hash
                 FROM cache_write_tickets
                 WHERE cache_id = ?1 AND state IN ('observing', 'active', 'completing')
                   AND active_cache_slot = 1 AND expires_at <= ?2
                   AND recovery_after <= ?2
                   AND (expires_at > ?3 OR (expires_at = ?3 AND ticket_id > ?4))
                 ORDER BY expires_at, ticket_id LIMIT ?5",
                &vals![cache_id, now, after_expires_at, after_ticket_id, limit],
            )
            .await?
            .iter()
            .map(row_to_cache_write_ticket)
            .collect()
    }

    /// Lists one global, cursor-ordered page of expired cache writes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid page limit, database failure, or malformed data.
    pub async fn list_expired_cache_write_tickets_global(
        &self,
        now: i64,
        after_expires_at: i64,
        after_ticket_id: &str,
        limit: i64,
    ) -> Result<Vec<CacheWriteTicketRecord>> {
        if !(1..=256).contains(&limit) {
            bail!("expired cache write ticket page limit must be between 1 and 256");
        }
        self.backend
            .query(
                "SELECT ticket_id, cache_id, object_key, declared_size, observed_final_size, uploaded_size, upload_kind,
                        placement_id, placement_resource_version,
                        placement_write_spec_version, binding_id,
                        binding_resource_version, binding_write_revision,
                        write_credential_purpose, write_credential_generation,
                        presign_credential_purpose, presign_credential_generation,
                        starting_inventory_generation, covered_inventory_generation,
                        backend_upload_id, state, expires_at, resource_version,
                        prior_object_size, prior_object_hash, prior_object_etag,
                        intended_object_hash
                 FROM cache_write_tickets
                 WHERE state IN ('observing', 'active', 'completing') AND active_cache_slot = 1
                   AND expires_at <= ?1 AND recovery_after <= ?1
                   AND (expires_at > ?2 OR (expires_at = ?2 AND ticket_id > ?3))
                 ORDER BY expires_at, ticket_id LIMIT ?4",
                &vals![now, after_expires_at, after_ticket_id, limit],
            )
            .await?
            .iter()
            .map(row_to_cache_write_ticket)
            .collect()
    }

    /// Returns the durable global cache-write recovery cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the cursor is missing or the database fails.
    pub async fn cache_write_recovery_cursor(&self) -> Result<(i64, String, i64)> {
        let row = self
            .backend
            .query_opt(
                "SELECT after_expires_at, after_ticket_id, resource_version
                 FROM write_recovery_cursors WHERE recovery_kind = 'cache'",
                &[],
            )
            .await?
            .context("cache write recovery cursor is missing")?;
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }

    /// Advances or wraps the durable global cache-write recovery cursor under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale cursor or database failure.
    pub async fn advance_cache_write_recovery_cursor(
        &self,
        expected_version: i64,
        after_expires_at: i64,
        after_ticket_id: &str,
        now: i64,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE write_recovery_cursors
                 SET after_expires_at = ?2, after_ticket_id = ?3,
                     resource_version = resource_version + 1, updated_at = ?4
                 WHERE recovery_kind = 'cache' AND resource_version = ?1",
                vals![expected_version, after_expires_at, after_ticket_id, now],
            )
            .expecting(1)])
            .await
    }

    /// Records a cache recovery failure and schedules bounded exponential retry.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale ticket or database failure.
    pub async fn defer_cache_write_recovery(
        &self,
        ticket_id: &str,
        expected_version: i64,
        now: i64,
        error: &str,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE cache_write_tickets
             SET state = CASE WHEN state = 'completing' AND recovery_attempts >= 7
                   THEN 'completed' ELSE state END,
                 active_cache_slot = CASE
                   WHEN state = 'completing' AND recovery_attempts >= 7 THEN NULL
                   ELSE active_cache_slot END,
                 quota_state = CASE
                   WHEN state = 'completing' AND recovery_attempts >= 7
                     AND quota_state = 'reserved' THEN 'committed'
                   ELSE quota_state END,
                 finished_at = CASE
                   WHEN state = 'completing' AND recovery_attempts >= 7 THEN ?3
                   ELSE finished_at END,
                 recovery_attempts = recovery_attempts + 1,
                 recovery_after = ?3 + CASE recovery_attempts
                   WHEN 0 THEN 15 WHEN 1 THEN 30 WHEN 2 THEN 60
                   WHEN 3 THEN 120 WHEN 4 THEN 240 WHEN 5 THEN 480
                   WHEN 6 THEN 960 WHEN 7 THEN 1920 ELSE 3600 END,
                 recovery_error = ?4, resource_version = resource_version + 1
             WHERE ticket_id = ?1 AND resource_version = ?2
               AND state IN ('observing', 'active', 'completing') AND active_cache_slot = 1",
                    vals![ticket_id, expected_version, now, error],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_gc_state SET epoch = epoch + 1,
                   epoch_owner_token = ?1, resource_version = resource_version + 1
                 WHERE cache_id = (SELECT cache_id FROM cache_write_tickets
                   WHERE ticket_id = ?1 AND state = 'completed'
                     AND finished_at = ?2)",
                    vals![ticket_id, now],
                )
                .unchecked(),
            ])
            .await
    }

    /// Converts one backend-cleaned expired ticket into an uncovered delta.
    ///
    /// The linked full inventory must cover the delta before GC may plan. The
    /// epoch advance and slot release are atomic, so an old reviewed plan can
    /// never race the recovery scan.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/non-expired ticket or database failure.
    pub async fn recover_expired_cache_write_ticket(
        &self,
        ticket_id: &str,
        expected_version: i64,
        now: i64,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE cache_write_tickets SET state = 'completed',
                   quota_state = CASE WHEN quota_state = 'reserved'
                     THEN 'committed' ELSE quota_state END,
                       active_cache_slot = NULL, finished_at = ?3,
                       resource_version = resource_version + 1
                     WHERE ticket_id = ?1 AND resource_version = ?2
                       AND state IN ('active', 'completing') AND active_cache_slot = 1
                       AND expires_at <= ?3",
                    vals![ticket_id, expected_version, now],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_gc_state SET epoch = epoch + 1,
                       epoch_owner_token = ?1, resource_version = resource_version + 1
                     WHERE cache_id = (SELECT cache_id FROM cache_write_tickets
                       WHERE ticket_id = ?1 AND state = 'completed'
                         AND finished_at = ?2)",
                    vals![ticket_id, now],
                )
                .expecting(1),
            ])
            .await
    }

    /// Preserves an ambiguous cache write as an inventory-uncovered delta.
    ///
    /// The declaration remains charged, the cache epoch advances, and a later
    /// complete inventory must cover the ticket before GC may plan. Negative or
    /// delayed backend evidence can therefore never release an attempted write.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/non-attempted state or database failure.
    pub async fn mark_cache_write_ticket_uncertain(
        &self,
        ticket_id: &str,
        expected_version: i64,
        now: i64,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE cache_write_tickets SET state = 'completed',
                       quota_state = CASE WHEN quota_state = 'reserved'
                         THEN 'committed' ELSE quota_state END,
                       active_cache_slot = NULL, finished_at = ?3,
                       resource_version = resource_version + 1
                     WHERE ticket_id = ?1 AND resource_version = ?2
                       AND state IN ('active', 'completing') AND active_cache_slot = 1",
                    vals![ticket_id, expected_version, now],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_gc_state SET epoch = epoch + 1,
                       epoch_owner_token = ?1, resource_version = resource_version + 1
                     WHERE cache_id = (SELECT cache_id FROM cache_write_tickets
                       WHERE ticket_id = ?1 AND state = 'completed'
                         AND finished_at = ?2)",
                    vals![ticket_id, now],
                )
                .expecting(1),
            ])
            .await
    }

    /// Reconciles an expired ambiguous cache write to current physical size.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid size, stale/non-expired state, or database failure.
    pub async fn observe_expired_cache_write_ticket_size(
        &self,
        ticket_id: &str,
        expected_version: i64,
        observed_size: i64,
        now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        if observed_size < 0 {
            bail!("observed cache write size is invalid");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE org_usage SET
                   used_bytes = CASE WHEN used_bytes + ?3 -
                     (SELECT declared_size FROM cache_write_tickets
                      WHERE ticket_id = ?1 AND resource_version = ?2) < 0
                     THEN 0 ELSE used_bytes + ?3 -
                     (SELECT declared_size FROM cache_write_tickets
                      WHERE ticket_id = ?1 AND resource_version = ?2) END,
                   updated_at = ?4
                 WHERE org_id = (SELECT quota_org_id FROM cache_write_tickets
                   WHERE ticket_id = ?1 AND resource_version = ?2
                     AND state IN ('active', 'completing') AND quota_state = 'reserved')",
                    vals![ticket_id, expected_version, observed_size, now],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE cache_write_tickets SET observed_final_size = ?3,
                   quota_delta_bytes = quota_delta_bytes + CASE
                     WHEN quota_org_id IS NOT NULL THEN ?3 - declared_size ELSE 0 END,
                   resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND state IN ('active', 'completing') AND expires_at <= ?4
                   AND observed_final_size IS NULL",
                    vals![ticket_id, expected_version, observed_size, now],
                )
                .expecting(1),
            ])
            .await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("observed cache ticket disappeared")
    }

    /// Records a placement observation for a direct upload without releasing its fence.
    ///
    /// A presigned URL remains replayable until expiry. Consequently this
    /// acknowledgement is evidence only; expiry recovery and a later complete
    /// inventory are still required before GC or topology changes may proceed.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/expired/non-presigned state, changed pinned
    /// identity, invalid evidence, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn acknowledge_presigned_cache_write_ticket(
        &self,
        ticket_id: &str,
        expected_version: i64,
        observed_etag: Option<&str>,
        observed_hash: Option<&str>,
        observed_size: i64,
        now: i64,
    ) -> Result<()> {
        if observed_hash.is_some_and(str::is_empty) || observed_size < 0 {
            bail!("presigned cache write acknowledgement evidence is invalid");
        }
        self.backend.checked_batch(&[Statement::new(
            "UPDATE cache_write_tickets
             SET direct_upload_acknowledged_at = ?6,
                 direct_upload_observed_etag = ?3,
                 direct_upload_observed_hash = ?4,
                 direct_upload_observed_size = ?5,
                 observed_final_size = ?5,
                 resource_version = resource_version + 1
             WHERE ticket_id = ?1 AND resource_version = ?2
               AND upload_kind = 'presigned' AND state = 'active'
               AND active_cache_slot = 1 AND expires_at > ?6
               AND declared_size = ?5
               AND direct_upload_acknowledged_at IS NULL
               AND EXISTS (SELECT 1 FROM surface_placement_effective placement
                 JOIN bindings binding ON binding.id = placement.binding_id
                 JOIN binding_credential_revisions write_credential
                   ON write_credential.binding_id = binding.id
                  AND write_credential.purpose = cache_write_tickets.write_credential_purpose
                  AND write_credential.generation = cache_write_tickets.write_credential_generation
                 JOIN binding_credential_revisions presign
                   ON presign.binding_id = binding.id
                  AND presign.purpose = cache_write_tickets.presign_credential_purpose
                  AND presign.generation = cache_write_tickets.presign_credential_generation
                 WHERE placement.id = cache_write_tickets.placement_id
                   AND placement.cache_id = cache_write_tickets.cache_id
                   AND placement.resource_version = cache_write_tickets.placement_resource_version
                   AND placement.write_spec_version = cache_write_tickets.placement_write_spec_version
                   AND placement.binding_id = cache_write_tickets.binding_id
                   AND placement.authority_observed_binding_write_revision = cache_write_tickets.binding_write_revision
                   AND binding.resource_version = cache_write_tickets.binding_resource_version
                   AND write_credential.validation_state = 'valid'
                   AND presign.validation_state = 'valid')",
            vals![
                ticket_id,
                expected_version,
                observed_etag,
                observed_hash,
                observed_size,
                now
            ],
        ).expecting(1)]).await
    }

    /// Reconciles a completed cache multipart upload to its backend-observed size.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/non-active state, invalid size, or database failure.
    pub async fn reconcile_cache_write_ticket_size(
        &self,
        ticket_id: &str,
        expected_version: i64,
        observed_size: i64,
        _now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        if observed_size < 0 {
            bail!("observed cache write size is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET observed_final_size = ?3,
                   resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND state = 'completing' AND upload_kind = 'multipart'
                   AND declared_size = ?3 AND uploaded_size = declared_size
                   AND observed_final_size IS NULL",
                vals![ticket_id, expected_version, observed_size],
            )
            .expecting(1)])
            .await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("reconciled cache ticket disappeared")
    }

    /// Claims the bounded provider-creation window for one multipart ticket.
    ///
    /// The provider operation itself cannot participate in the database
    /// transaction. This lease serializes attempts; a backend advertising
    /// multipart support must separately guarantee bounded cleanup of an
    /// incomplete provider upload whose response is lost.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, expired, already-attached, or currently
    /// claimed ticket, invalid identity, or database failure.
    pub async fn claim_cache_write_backend_creation(
        &self,
        ticket_id: &str,
        expected_version: i64,
        create_token: &str,
        lease_expires_at: i64,
        now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        validate_stable_key(create_token, "cache backend creation token")?;
        if lease_expires_at <= now {
            bail!("cache backend creation lease is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets
                 SET backend_create_token = ?3, backend_create_expires_at = ?4,
                     resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND upload_kind = 'multipart' AND state = 'active'
                   AND active_cache_slot = 1 AND backend_upload_id IS NULL
                   AND expires_at > ?5
                   AND (backend_create_token IS NULL
                     OR backend_create_expires_at <= ?5)",
                vals![
                    ticket_id,
                    expected_version,
                    create_token,
                    lease_expires_at,
                    now
                ],
            )
            .expecting(1)])
            .await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("claimed cache backend creation ticket disappeared")
    }

    /// Attaches the opaque backend multipart id under ticket and creation-owner CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/expired/non-multipart ticket or database failure.
    pub async fn attach_cache_write_backend_upload(
        &self,
        ticket_id: &str,
        expected_version: i64,
        expected_create_token: &str,
        backend_upload_id: &str,
        now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        validate_stable_key(expected_create_token, "cache backend creation token")?;
        if backend_upload_id.is_empty() {
            bail!("backend multipart upload id is empty");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets
                 SET backend_upload_id = ?4, backend_create_token = NULL,
                     backend_create_expires_at = NULL,
                     resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND upload_kind = 'multipart' AND state = 'active'
                   AND backend_upload_id IS NULL AND backend_create_token = ?3
                   AND backend_create_expires_at > ?5 AND expires_at > ?5",
                vals![
                    ticket_id,
                    expected_version,
                    expected_create_token,
                    backend_upload_id,
                    now
                ],
            )
            .expecting(1)])
            .await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("multipart cache write ticket disappeared")
    }

    /// Durably admits one cache multipart part without exceeding declared size.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative part size, stale/non-active ticket,
    /// declared-size overflow, or database failure.
    pub async fn admit_cache_write_part(
        &self,
        ticket_id: &str,
        expected_version: i64,
        part_number: u32,
        part_size: i64,
        body_digest: &str,
    ) -> Result<CacheWriteTicketRecord> {
        validate_part_body_identity(part_number, part_size, body_digest)?;
        if part_number == 0 || part_size <= 0 {
            bail!("multipart part size is invalid");
        }
        if let Some(existing) = self.cache_write_ticket_part(ticket_id, part_number).await? {
            require_same_part_body(&existing, part_size, body_digest)?;
            let ticket = self
                .cache_write_ticket(ticket_id)
                .await?
                .context("multipart cache write ticket disappeared")?;
            if ticket.resource_version < expected_version || ticket.state != "active" {
                bail!("multipart cache write ticket is stale");
            }
            return Ok(ticket);
        }
        let admission = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO cache_write_ticket_parts
                     (ticket_id, part_number, admitted_size, body_digest, state)
                     SELECT ticket_id, ?3, ?4, ?5, 'admitted'
                     FROM cache_write_tickets
                     WHERE ticket_id = ?1 AND resource_version >= ?2
                       AND state = 'active' AND upload_kind = 'multipart'
                       AND uploaded_size + ?4 <= declared_size",
                    vals![
                        ticket_id,
                        expected_version,
                        i64::from(part_number),
                        part_size,
                        body_digest
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_write_tickets
                     SET uploaded_size = uploaded_size + ?4,
                         resource_version = resource_version + 1
                     WHERE ticket_id = ?1 AND resource_version >= ?2
                       AND state = 'active' AND upload_kind = 'multipart'
                       AND EXISTS (SELECT 1 FROM cache_write_ticket_parts part
                         WHERE part.ticket_id = ?1 AND part.part_number = ?3
                           AND part.admitted_size = ?4 AND part.body_digest = ?5)
                       AND uploaded_size + ?4 <= declared_size",
                    vals![
                        ticket_id,
                        expected_version,
                        i64::from(part_number),
                        part_size,
                        body_digest
                    ],
                )
                .expecting(1),
            ])
            .await;
        if let Err(error) = admission {
            // A simultaneous request for the same primary key can lose the
            // checked insert after the winner has committed its parent-size
            // increment. Reread that winner and accept only the exact body in
            // an admissible active ticket; a different identity is a hard
            // conflict and every other failure preserves the original error.
            for _ in 0..3 {
                let Ok(Some(existing)) = self.cache_write_ticket_part(ticket_id, part_number).await
                else {
                    continue;
                };
                if matches!(
                    existing.state.as_str(),
                    "admitted" | "ambiguous" | "confirmed"
                ) {
                    require_same_part_body(&existing, part_size, body_digest)?;
                    if let Ok(Some(ticket)) = self.cache_write_ticket(ticket_id).await {
                        if ticket.state == "active"
                            && ticket.resource_version >= expected_version
                            && ticket.uploaded_size >= existing.admitted_size
                            && ticket.uploaded_size <= ticket.declared_size
                        {
                            return Ok(ticket);
                        }
                    }
                }
            }
            return Err(error);
        }
        self.cache_write_ticket(ticket_id)
            .await?
            .context("admitted cache multipart ticket disappeared")
    }

    /// Returns one durable cache multipart-part admission.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, malformed persisted data, or database failure.
    pub async fn cache_write_ticket_part(
        &self,
        ticket_id: &str,
        part_number: u32,
    ) -> Result<Option<WriteTicketPartRecord>> {
        if part_number == 0 {
            bail!("multipart part number is invalid");
        }
        self.backend
            .query_opt(
                "SELECT part_number, admitted_size, body_digest, state, etag
                 FROM cache_write_ticket_parts
                 WHERE ticket_id = ?1 AND part_number = ?2",
                &vals![ticket_id, i64::from(part_number)],
            )
            .await?
            .map(|row| row_to_write_ticket_part(&row))
            .transpose()
    }

    /// Marks a cache multipart part as possibly accepted after an opaque backend error.
    pub async fn mark_cache_write_part_ambiguous(
        &self,
        ticket_id: &str,
        expected_version: i64,
        part_number: u32,
    ) -> Result<()> {
        self.transition_cache_write_part(
            ticket_id,
            expected_version,
            part_number,
            "ambiguous",
            None,
        )
        .await
    }

    /// Confirms a cache multipart part and stores its backend completion identity.
    pub async fn confirm_cache_write_part(
        &self,
        ticket_id: &str,
        expected_version: i64,
        part_number: u32,
        etag: &str,
    ) -> Result<()> {
        self.transition_cache_write_part(
            ticket_id,
            expected_version,
            part_number,
            "confirmed",
            Some(etag),
        )
        .await
    }

    async fn transition_cache_write_part(
        &self,
        ticket_id: &str,
        expected_version: i64,
        part_number: u32,
        state: &str,
        etag: Option<&str>,
    ) -> Result<()> {
        if part_number == 0 || !matches!(state, "ambiguous" | "confirmed") {
            bail!("multipart part transition is invalid");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE cache_write_ticket_parts
                     SET state = CASE WHEN state = 'confirmed' THEN state ELSE ?4 END,
                         etag = CASE WHEN state = 'confirmed' THEN etag ELSE ?5 END
                     WHERE ticket_id = ?1 AND part_number = ?3
                       AND (state IN ('admitted', 'ambiguous')
                         OR (state = 'confirmed' AND ?4 = 'ambiguous')
                         OR (state = 'confirmed' AND ?4 = 'confirmed' AND etag = ?5))
                       AND EXISTS (SELECT 1 FROM cache_write_tickets ticket
                         WHERE ticket.ticket_id = ?1 AND ticket.resource_version >= ?2
                           AND ticket.state = 'active')",
                    vals![
                        ticket_id,
                        expected_version,
                        i64::from(part_number),
                        state,
                        etag
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_write_tickets SET resource_version = resource_version + 1
                     WHERE ticket_id = ?1 AND resource_version >= ?2 AND state = 'active'",
                    vals![ticket_id, expected_version],
                )
                .expecting(1),
            ])
            .await
    }

    /// Lists every cache multipart part in completion order.
    pub async fn cache_write_ticket_parts(
        &self,
        ticket_id: &str,
    ) -> Result<Vec<WriteTicketPartRecord>> {
        self.backend
            .query(
                "SELECT part_number, admitted_size, body_digest, state, etag
                 FROM cache_write_ticket_parts WHERE ticket_id = ?1 ORDER BY part_number",
                &vals![ticket_id],
            )
            .await?
            .iter()
            .map(row_to_write_ticket_part)
            .collect()
    }

    /// Durably records cache multipart completion intent before backend mutation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the ticket is active, unexpired, fully uploaded,
    /// and owns exactly the contiguous confirmed part set `1..=N`.
    pub async fn begin_cache_multipart_completion(
        &self,
        ticket_id: &str,
        expected_version: i64,
        now: i64,
    ) -> Result<CacheWriteTicketRecord> {
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET state = 'completing',
               resource_version = resource_version + 1
             WHERE ticket_id = ?1 AND resource_version = ?2
               AND state = 'active' AND active_cache_slot = 1
               AND upload_kind = 'multipart' AND expires_at > ?3
               AND uploaded_size = declared_size
               AND NOT EXISTS (SELECT 1 FROM cache_write_ticket_parts part
                 WHERE part.ticket_id = cache_write_tickets.ticket_id
                   AND part.state <> 'confirmed')
               AND declared_size = (SELECT COALESCE(SUM(part.admitted_size), 0)
                 FROM cache_write_ticket_parts part
                 WHERE part.ticket_id = cache_write_tickets.ticket_id)
               AND 1 = (SELECT COALESCE(MIN(part.part_number), 0)
                 FROM cache_write_ticket_parts part
                 WHERE part.ticket_id = cache_write_tickets.ticket_id)
               AND (SELECT COUNT(*) FROM cache_write_ticket_parts part
                 WHERE part.ticket_id = cache_write_tickets.ticket_id)
                 = (SELECT COALESCE(MAX(part.part_number), 0)
                 FROM cache_write_ticket_parts part
                 WHERE part.ticket_id = cache_write_tickets.ticket_id)",
                vals![ticket_id, expected_version, now],
            )
            .expecting(1)])
            .await?;
        self.cache_write_ticket(ticket_id)
            .await?
            .context("completing cache ticket disappeared")
    }

    /// Resolves a live ticket only while every pinned topology identity matches.
    ///
    /// Callers may opt into a completing multipart ticket when replaying its
    /// immutable part set or deterministic provider completion. Other write
    /// paths continue to require `active`.
    ///
    /// # Errors
    ///
    /// Returns an error for expiry, retarget, credential rotation, path mismatch,
    /// stale inventory, or database failure.
    pub async fn validate_cache_write_ticket(
        &self,
        ticket_id: &str,
        cache_id: i64,
        object_key: &str,
        now: i64,
        allow_completing_multipart: bool,
    ) -> Result<CacheWriteTicketRecord> {
        let row = self
            .backend
            .query_opt(
                "SELECT ticket.ticket_id, ticket.cache_id, ticket.object_key,
                        ticket.declared_size, ticket.observed_final_size,
                        ticket.uploaded_size, ticket.upload_kind, ticket.placement_id,
                        ticket.placement_resource_version,
                        ticket.placement_write_spec_version,
                        ticket.binding_id, ticket.binding_resource_version,
                        ticket.binding_write_revision,
                        ticket.write_credential_purpose,
                        ticket.write_credential_generation,
                        ticket.presign_credential_purpose,
                        ticket.presign_credential_generation,
                        ticket.starting_inventory_generation,
                        ticket.covered_inventory_generation,
                        ticket.backend_upload_id, ticket.state,
                        ticket.expires_at, ticket.resource_version,
                        ticket.prior_object_size, ticket.prior_object_hash,
                        ticket.prior_object_etag, ticket.intended_object_hash
                 FROM cache_write_tickets ticket
                 JOIN surface_placement_effective placement
                   ON placement.id = ticket.placement_id
                  AND placement.cache_id = ticket.cache_id
                 JOIN bindings binding
                   ON binding.id = ticket.binding_id
                 JOIN binding_credential_revisions credential
                   ON credential.binding_id = ticket.binding_id
                  AND credential.purpose = ticket.write_credential_purpose
                  AND credential.generation = ticket.write_credential_generation
                 LEFT JOIN binding_credential_revisions presign
                   ON presign.binding_id = ticket.binding_id
                  AND presign.purpose = ticket.presign_credential_purpose
                  AND presign.generation = ticket.presign_credential_generation
                 JOIN cache_gc_state state ON state.cache_id = ticket.cache_id
                 WHERE ticket.ticket_id = ?1 AND ticket.cache_id = ?2
                   AND ticket.object_key = ?3
                   AND (ticket.state = 'active' OR (?5 = 1
                     AND ticket.upload_kind = 'multipart'
                     AND ticket.state = 'completing'))
                   AND ticket.active_cache_slot = 1 AND ticket.expires_at > ?4
                   AND placement.resource_version = ticket.placement_resource_version
                   AND placement.write_spec_version = ticket.placement_write_spec_version
                   AND placement.binding_id = ticket.binding_id
                   AND placement.authority_observed_binding_write_revision
                     = ticket.binding_write_revision
                   AND placement.effective_write_enabled = 1
                   AND binding.resource_version = ticket.binding_resource_version
                   AND credential.validation_state = 'valid'
                   AND (ticket.presign_credential_generation IS NULL
                     OR presign.validation_state = 'valid')
                   AND state.inventory_generation
                     = ticket.starting_inventory_generation",
                &vals![
                    ticket_id,
                    cache_id,
                    object_key,
                    now,
                    allow_completing_multipart
                ],
            )
            .await?
            .context("cache write ticket is stale, expired, or retargeted")?;
        row_to_cache_write_ticket(&row)
    }

    /// Finalizes a write as an uncovered durable inventory delta.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/expired ticket, changed physical identity,
    /// invalid immutable credential revision, or database failure.
    pub async fn complete_cache_write_ticket(
        &self,
        ticket_id: &str,
        expected_version: i64,
        now: i64,
    ) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE cache_write_tickets SET state = 'completed',
                       observed_final_size = CASE WHEN upload_kind = 'single'
                         THEN declared_size ELSE observed_final_size END,
                       quota_state = CASE WHEN quota_state = 'reserved'
                         THEN 'committed' ELSE quota_state END,
                   active_cache_slot = NULL, finished_at = ?3,
                   resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND ((upload_kind = 'single' AND state = 'active')
                     OR (upload_kind = 'multipart' AND state = 'completing'))
                   AND active_cache_slot = 1
                   AND upload_kind <> 'presigned'
                   AND (upload_kind = 'single' OR (upload_kind = 'multipart'
                     AND observed_final_size = declared_size
                     AND uploaded_size = declared_size
                     AND NOT EXISTS (SELECT 1 FROM cache_write_ticket_parts part
                       WHERE part.ticket_id = cache_write_tickets.ticket_id
                         AND part.state <> 'confirmed')
                     AND declared_size = (SELECT COALESCE(SUM(part.admitted_size), 0)
                       FROM cache_write_ticket_parts part
                       WHERE part.ticket_id = cache_write_tickets.ticket_id
                         AND part.state = 'confirmed')))
                   AND expires_at > ?3
                   AND EXISTS (SELECT 1 FROM surface_placement_effective placement
                     JOIN bindings binding
                       ON binding.id = placement.binding_id
                     JOIN binding_credential_revisions credential
                       ON credential.binding_id = binding.id
                      AND credential.purpose
                        = cache_write_tickets.write_credential_purpose
                      AND credential.generation
                        = cache_write_tickets.write_credential_generation
                     WHERE placement.id = cache_write_tickets.placement_id
                       AND placement.cache_id = cache_write_tickets.cache_id
                       AND placement.resource_version
                         = cache_write_tickets.placement_resource_version
                       AND placement.write_spec_version
                         = cache_write_tickets.placement_write_spec_version
                       AND placement.binding_id
                         = cache_write_tickets.binding_id
                       AND placement.authority_observed_binding_write_revision
                         = cache_write_tickets.binding_write_revision
                       AND binding.resource_version
                         = cache_write_tickets.binding_resource_version
                       AND credential.validation_state = 'valid')",
                    vals![ticket_id, expected_version, now],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_gc_state SET epoch = epoch + 1,
                       epoch_owner_token = ?1, resource_version = resource_version + 1
                     WHERE cache_id = (SELECT cache_id FROM cache_write_tickets
                       WHERE ticket_id = ?1 AND state = 'completed'
                         AND finished_at = ?2)",
                    vals![ticket_id, now],
                )
                .expecting(1),
            ])
            .await
    }

    /// Releases a ticket after a backend-confirmed abort or pre-write failure.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state or database failure.
    pub async fn abort_cache_write_ticket(
        &self,
        ticket_id: &str,
        expected_version: i64,
        state: &str,
        now: i64,
    ) -> Result<()> {
        if !matches!(state, "aborted" | "failed") {
            bail!("cache write terminal state is invalid");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE org_usage
                     SET used_bytes = CASE
                           WHEN used_bytes - (SELECT quota_delta_bytes
                             FROM cache_write_tickets WHERE ticket_id = ?1) < 0
                           THEN 0 ELSE used_bytes - (SELECT quota_delta_bytes
                             FROM cache_write_tickets WHERE ticket_id = ?1) END,
                         object_count = CASE
                           WHEN object_count - (SELECT quota_delta_objects
                             FROM cache_write_tickets WHERE ticket_id = ?1) < 0
                           THEN 0 ELSE object_count - (SELECT quota_delta_objects
                             FROM cache_write_tickets WHERE ticket_id = ?1) END,
                         updated_at = ?4
                     WHERE org_id = (SELECT quota_org_id FROM cache_write_tickets
                       WHERE ticket_id = ?1 AND resource_version = ?2
                         AND state IN ('observing', 'active') AND quota_state = 'reserved')",
                    vals![ticket_id, expected_version, state, now],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE cache_write_tickets SET state = ?3,
                   quota_state = CASE WHEN quota_state IN ('pending', 'reserved')
                     THEN 'released' ELSE quota_state END,
                   active_cache_slot = NULL, finished_at = ?4,
                   resource_version = resource_version + 1
                 WHERE ticket_id = ?1 AND resource_version = ?2
                   AND state IN ('observing', 'active') AND active_cache_slot = 1",
                    vals![ticket_id, expected_version, state, now],
                )
                .expecting(1),
            ])
            .await
    }

    async fn cache_gc_generation_topology_digest(
        &self,
        cache_id: i64,
        generation_id: &str,
    ) -> Result<String> {
        let rows = self
            .backend
            .query(
                "SELECT placement_id, placement_resource_version,
                   placement_name, binding_id,
                   binding_stable_id,
                   binding_resource_version, prefix, placement_kind,
                   desired_state, write_spec_version,
                   requires_conditional_writes
                 FROM cache_gc_generation_placements
                 WHERE cache_id = ?1 AND generation_id = ?2
                 ORDER BY placement_id",
                &vals![cache_id, generation_id],
            )
            .await?;
        let placements = rows
            .iter()
            .map(|row| {
                Ok(serde_json::json!({
                    "placement_id": row.get::<i64>(0)?,
                    "placement_resource_version": row.get::<i64>(1)?,
                    "placement_name": row.get::<String>(2)?,
                    "binding_id": row.get::<i64>(3)?,
                    "binding_stable_id": row.get::<String>(4)?,
                    "binding_resource_version": row.get::<i64>(5)?,
                    "prefix": row.get::<String>(6)?,
                    "placement_kind": row.get::<String>(7)?,
                    "desired_state": row.get::<String>(8)?,
                    "write_spec_version": row.get::<i64>(9)?,
                    "requires_conditional_writes": row.get::<bool>(10)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(digest_text(&serde_json::to_string(&placements)?))
    }

    async fn cache_gc_generation_input_versions_digest(
        &self,
        cache_id: i64,
        generation_id: &str,
    ) -> Result<String> {
        let generation = self
            .backend
            .query_opt(
                "SELECT expected_epoch, root_generation,
                   object_graph_generation, inventory_generation,
                   gc_policy_version, topology_version, root_count,
                   marked_object_count, coverage_error_count,
                   parent_mark_generation_id
                 FROM cache_gc_generations
                 WHERE cache_id = ?1 AND generation_id = ?2
                   AND state = 'complete'",
                &vals![cache_id, generation_id],
            )
            .await?
            .context("cache GC generation is not complete")?;
        let topology_snapshot_digest = self
            .cache_gc_generation_topology_digest(cache_id, generation_id)
            .await?;
        Ok(digest_text(&format!(
            "cache={};epoch={};roots={};graph={};inventory={};policy={};topology={};topology_snapshot={};root_count={};mark_count={};coverage_errors={};parent_mark={:?}",
            cache_id,
            generation.get::<i64>(0)?,
            generation.get::<i64>(1)?,
            generation.get::<i64>(2)?,
            generation.get::<i64>(3)?,
            generation.get::<i64>(4)?,
            generation.get::<i64>(5)?,
            topology_snapshot_digest,
            generation.get::<i64>(6)?,
            generation.get::<i64>(7)?,
            generation.get::<i64>(8)?,
            generation.get::<Option<String>>(9)?,
        )))
    }

    /// Creates the one reviewed acknowledgement that may open destructive GC.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a stale/mismatched GC plan, an
    /// already-open gate, duplicate identity, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_cache_gc_first_sweep_acknowledgement(
        &self,
        acknowledgement_id: &str,
        cache_id: i64,
        gc_plan_id: &str,
        expected_cache_epoch: i64,
        expected_gc_policy_version: i64,
        gc_manifest_digest: &str,
        confirmation_hash: &str,
        created_by: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        validate_stable_key(acknowledgement_id, "first-sweep acknowledgement id")?;
        validate_stable_key(gc_plan_id, "cache GC plan id")?;
        if cache_id <= 0
            || expected_cache_epoch < 0
            || expected_gc_policy_version <= 0
            || gc_manifest_digest.is_empty()
            || confirmation_hash.is_empty()
            || created_by.trim().is_empty()
            || expires_at <= created_at
        {
            bail!("first-sweep acknowledgement input is invalid");
        }
        if self
            .backend
            .query_opt(
                "SELECT acknowledgement_id
                 FROM cache_gc_first_sweep_acknowledgements
                 WHERE acknowledgement_id = ?1 AND cache_id = ?2
                   AND gc_plan_id = ?3
                   AND state IN ('planned', 'applied')
                   AND expected_cache_epoch = ?4
                   AND expected_gc_policy_version = ?5
                   AND gc_manifest_digest = ?6
                   AND confirmation_hash = ?7
                   AND created_by = ?8",
                &vals![
                    acknowledgement_id,
                    cache_id,
                    gc_plan_id,
                    expected_cache_epoch,
                    expected_gc_policy_version,
                    gc_manifest_digest,
                    confirmation_hash,
                    created_by
                ],
            )
            .await?
            .is_some()
        {
            return Ok(());
        }
        let statement = Statement::new(
            "INSERT INTO cache_gc_first_sweep_acknowledgements
             (acknowledgement_id, cache_id, gc_plan_id, state,
              expected_cache_epoch, expected_gc_policy_version,
              gc_manifest_digest, confirmation_hash, created_by,
              created_at, expires_at)
             SELECT ?1, plan.cache_id, plan.plan_id, 'planned', ?4, ?5,
                    ?6, ?7, ?8, ?9, ?10
             FROM cache_gc_plans plan
             JOIN cache_gc_state state ON state.cache_id = plan.cache_id
             JOIN cache_gc_heads head ON head.cache_id = state.cache_id
             JOIN cache_gc_policies policy ON policy.cache_id = plan.cache_id
             WHERE plan.cache_id = ?2 AND plan.plan_id = ?3
               AND plan.expected_epoch = ?4 AND plan.manifest_digest = ?6
               AND plan.confirmation_hash = ?7
               AND plan.created_at <= ?9 AND plan.expires_at > ?9
               AND plan.applied_at IS NULL
               AND EXISTS (SELECT 1 FROM cache_gc_plan_build_assertions assertion
                 WHERE assertion.cache_id = plan.cache_id
                   AND assertion.plan_id = plan.plan_id AND assertion.ok = 1)
               AND state.epoch = ?4 AND state.destructive_enabled = 0
               AND head.first_sweep_acknowledgement_id IS NULL
               AND head.current_mark_generation_id = plan.generation_id
               AND policy.resource_version = ?5",
            vals![
                acknowledgement_id,
                cache_id,
                gc_plan_id,
                expected_cache_epoch,
                expected_gc_policy_version,
                gc_manifest_digest,
                confirmation_hash,
                created_by,
                created_at,
                expires_at
            ],
        )
        .expecting(1);
        self.backend.checked_batch(&[statement]).await
    }
    /// Atomically opens destructive GC and invalidates the acknowledged plan.
    ///
    /// This transition deliberately does not apply the GC plan. Advancing the
    /// cache epoch makes that plan stale, so the caller must build and review a
    /// fresh plan before any logical tombstone or physical deletion job can be
    /// created.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, expired, or mismatched acknowledgement or
    /// plan, invalid identities, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_cache_gc_first_sweep_acknowledgement(
        &self,
        acknowledgement_id: &str,
        claim_id: &str,
        actor_scope_digest: &str,
        confirmation_hash: &str,
        acknowledged_by: &str,
        acknowledged_at: i64,
    ) -> Result<String> {
        validate_stable_key(acknowledgement_id, "first-sweep acknowledgement id")?;
        validate_stable_key(claim_id, "first-sweep epoch claim id")?;
        if actor_scope_digest.is_empty()
            || confirmation_hash.is_empty()
            || acknowledged_by.trim().is_empty()
        {
            bail!("first-sweep acknowledgement apply input is invalid");
        }

        if self
            .backend
            .query_opt(
                "SELECT acknowledgement.acknowledgement_id
                 FROM cache_gc_first_sweep_acknowledgements acknowledgement
                 JOIN cache_gc_plans plan ON plan.plan_id = acknowledgement.gc_plan_id
                   AND plan.cache_id = acknowledgement.cache_id
                 WHERE acknowledgement.acknowledgement_id = ?1
                   AND acknowledgement.state = 'applied'
                   AND acknowledgement.confirmation_hash = ?2
                   AND acknowledgement.acknowledged_by = ?3
                   AND plan.actor_scope_digest = ?4",
                &vals![
                    acknowledgement_id,
                    confirmation_hash,
                    acknowledged_by,
                    actor_scope_digest
                ],
            )
            .await?
            .is_some()
        {
            return Ok(acknowledgement_id.to_string());
        }

        let row = self
            .backend
            .query_opt(
                "SELECT acknowledgement.cache_id,
                        acknowledgement.expected_cache_epoch
                 FROM cache_gc_first_sweep_acknowledgements acknowledgement
                 JOIN cache_gc_plans plan ON plan.plan_id = acknowledgement.gc_plan_id
                   AND plan.cache_id = acknowledgement.cache_id
                 JOIN cache_gc_state state ON state.cache_id = acknowledgement.cache_id
                 JOIN cache_gc_policies policy ON policy.cache_id = state.cache_id
                 WHERE acknowledgement.acknowledgement_id = ?1
                   AND acknowledgement.state = 'planned'
                   AND acknowledgement.confirmation_hash = ?2
                   AND acknowledgement.gc_manifest_digest = plan.manifest_digest
                   AND acknowledgement.expected_cache_epoch = plan.expected_epoch
                   AND acknowledgement.expected_gc_policy_version
                     = policy.resource_version
                   AND plan.actor_scope_digest = ?3
                   AND plan.confirmation_hash = ?2
                   AND plan.applied_at IS NULL
                   AND acknowledgement.expires_at > ?4
                   AND plan.expires_at > ?4
                   AND state.epoch = acknowledgement.expected_cache_epoch
                   AND state.destructive_enabled = 0",
                &vals![
                    acknowledgement_id,
                    confirmation_hash,
                    actor_scope_digest,
                    acknowledged_at
                ],
            )
            .await?
            .context("first-sweep acknowledgement is stale, expired, or mismatched")?;
        let cache_id: i64 = row.get(0)?;
        let expected_epoch: i64 = row.get(1)?;
        let statements = [
            Statement::new(
                "UPDATE cache_gc_first_sweep_acknowledgements
                 SET state = 'applied', acknowledged_by = ?2,
                     acknowledged_at = ?3
                 WHERE acknowledgement_id = ?1 AND state = 'planned'
                   AND confirmation_hash = ?4 AND expires_at > ?3",
                vals![
                    acknowledgement_id,
                    acknowledged_by,
                    acknowledged_at,
                    confirmation_hash
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_gc_state
                 SET epoch = epoch + 1, epoch_owner_token = ?3,
                     topology_generation = topology_generation + 1,
                     destructive_enabled = 1,
                     resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND epoch = ?2
                   AND destructive_enabled = 0
                   AND NOT EXISTS (
                     SELECT 1 FROM surface_placement_effective placement
                     LEFT JOIN bindings binding
                       ON binding.id = placement.binding_id
                     LEFT JOIN binding_write_revisions revision
                       ON revision.binding_id = placement.binding_id
                      AND revision.revision = placement.authority_observed_binding_write_revision
                     WHERE placement.cache_id = ?1
                       AND (COALESCE(binding.kind, '') = 'r2'
                         OR placement.requires_conditional_writes <> 1
                         OR COALESCE(revision.conditional_writes_supported, 0) <> 1))
                   AND EXISTS (SELECT 1
                     FROM cache_gc_first_sweep_acknowledgements acknowledgement
                     WHERE acknowledgement.acknowledgement_id = ?4
                       AND acknowledgement.cache_id = ?1
                       AND acknowledgement.state = 'applied')",
                vals![cache_id, expected_epoch, claim_id, acknowledgement_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_gc_heads
                 SET first_sweep_acknowledgement_id = ?2,
                     first_sweep_acknowledgement_state = 'applied',
                     first_sweep_acknowledged_at = ?3,
                     resource_version = resource_version + 1,
                     updated_at = ?3
                 WHERE cache_id = ?1
                   AND first_sweep_acknowledgement_id IS NULL
                   AND EXISTS (SELECT 1
                     FROM cache_gc_first_sweep_acknowledgements acknowledgement
                     WHERE acknowledgement.acknowledgement_id = ?2
                       AND acknowledgement.cache_id = ?1
                       AND acknowledgement.state = 'applied')",
                vals![cache_id, acknowledgement_id, acknowledged_at],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_epoch_assertions
                 (mutation_id, cache_id, expected_epoch, resulting_epoch,
                  epoch_owner_token, mutation_kind, ok, asserted_at)
                 VALUES (?1, ?2, ?3, ?3 + 1, ?1, 'topology',
                   CASE WHEN EXISTS (SELECT 1 FROM cache_gc_state
                     WHERE cache_id = ?2 AND epoch = ?3 + 1
                       AND epoch_owner_token = ?1 AND destructive_enabled = 1)
                     AND EXISTS (SELECT 1 FROM cache_gc_heads
                       WHERE cache_id = ?2
                         AND first_sweep_acknowledgement_id = ?4
                         AND first_sweep_acknowledgement_state = 'applied')
                   THEN 1 ELSE 0 END, ?5)",
                vals![
                    claim_id,
                    cache_id,
                    expected_epoch,
                    acknowledgement_id,
                    acknowledged_at
                ],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await?;
        Ok(acknowledgement_id.to_string())
    }
    pub async fn initialize_cache_gc_topology(
        &self,
        policy: &CacheGcPolicyRecord,
        inventory_generation: i64,
        epoch_owner_token: &str,
    ) -> Result<()> {
        validate_gc_policy(policy)?;
        validate_stable_key(epoch_owner_token, "initial cache epoch owner")?;
        if inventory_generation <= 0 {
            bail!("initial cache inventory generation must be positive");
        }
        let statements = vec![
            Statement::new(
                "INSERT INTO cache_gc_policies
                 (cache_id, unreferenced_grace_secs, soft_max_bytes,
                  soft_max_objects, schedule_secs, deletion_concurrency,
                  retry_initial_secs, retry_max_secs, retry_max_attempts,
                  tombstone_retention_secs, resource_version)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1
                 FROM binary_caches WHERE id = ?1",
                vals![
                    policy.cache_id,
                    policy.unreferenced_grace_secs,
                    policy.soft_max_bytes,
                    policy.soft_max_objects,
                    policy.schedule_secs,
                    policy.deletion_concurrency,
                    policy.retry_initial_secs,
                    policy.retry_max_secs,
                    policy.retry_max_attempts,
                    policy.tombstone_retention_secs
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_state
                 (cache_id, epoch, epoch_owner_token, root_generation,
                  object_graph_generation, inventory_generation,
                  topology_generation, destructive_enabled, resource_version)
                 SELECT inventory.cache_id, 0, ?3, 0, 0,
                        inventory.generation, 0, 0, 1
                 FROM cache_inventory_generations inventory
                 WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                   AND inventory.state = 'published'",
                vals![policy.cache_id, inventory_generation, epoch_owner_token],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_deletion_capacity (cache_id, running_count)
                 VALUES (?1, 0)",
                vals![policy.cache_id],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_heads
                 (cache_id, resource_version, updated_at)
                 SELECT ?1, 1, 0 FROM cache_gc_state WHERE cache_id = ?1",
                vals![policy.cache_id],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Replaces cache-global sweep mechanics under policy-version and epoch CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy, stale versions, or database failure.
    pub async fn set_cache_gc_policy_topology(
        &self,
        policy: &CacheGcPolicyRecord,
        expected_epoch: i64,
        mutation_id: &str,
        updated_at: i64,
    ) -> Result<()> {
        validate_gc_policy(policy)?;
        validate_stable_key(mutation_id, "cache GC policy mutation id")?;
        if expected_epoch < 0 || policy.resource_version <= 0 {
            bail!("expected cache epoch and policy version are invalid");
        }
        let statements = vec![
            Statement::new(
                "UPDATE cache_gc_policies SET unreferenced_grace_secs = ?2,
                   soft_max_bytes = ?3, soft_max_objects = ?4,
                   schedule_secs = ?5, deletion_concurrency = ?6,
                   retry_initial_secs = ?7, retry_max_secs = ?8,
                   retry_max_attempts = ?9, tombstone_retention_secs = ?10,
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND resource_version = ?11",
                vals![
                    policy.cache_id,
                    policy.unreferenced_grace_secs,
                    policy.soft_max_bytes,
                    policy.soft_max_objects,
                    policy.schedule_secs,
                    policy.deletion_concurrency,
                    policy.retry_initial_secs,
                    policy.retry_max_secs,
                    policy.retry_max_attempts,
                    policy.tombstone_retention_secs,
                    policy.resource_version
                ],
            )
            .expecting(1),
            epoch_update_statement(
                policy.cache_id,
                expected_epoch,
                mutation_id,
                "root_generation = root_generation",
            ),
            epoch_assertion_statement(
                mutation_id,
                policy.cache_id,
                expected_epoch,
                "policy",
                updated_at,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_gc_policies WHERE cache_id = {} AND resource_version = {})",
                    policy.cache_id,
                    policy.resource_version + 1
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Advances the cache topology generation after a placement or route mutation.
    ///
    /// Callers must include this statement in the same higher-level checked
    /// transaction as the topology mutation; the method is exposed for
    /// reconcilers whose topology write is already durable and must establish
    /// a new GC planning fence before further work.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid token, stale cache epoch, or database
    /// failure.
    pub async fn advance_cache_gc_topology_generation(
        &self,
        cache_id: i64,
        expected_epoch: i64,
        mutation_id: &str,
        changed_at: i64,
    ) -> Result<()> {
        validate_stable_key(mutation_id, "cache topology mutation id")?;
        let statements = vec![
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "topology_generation = topology_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "topology",
                changed_at,
                "1 = 1",
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Persists a complete immutable relational GC plan.
    ///
    /// The final checked assertion proves complete physical action coverage and
    /// narinfo-before-NAR dependency edges, including shared NAR fan-in.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/duplicate manifest entries, stale mark or
    /// presence inputs, incomplete action coverage/dependencies, an unsafe
    /// grace candidate, or database failure.
    pub async fn create_cache_gc_plan_topology(&self, input: &CreateCacheGcPlan) -> Result<()> {
        self.assert_cache_gc_delete_topology_supported(input.cache_id)
            .await?;
        validate_stable_key(&input.plan_id, "cache GC plan id")?;
        validate_stable_key(&input.generation_id, "cache GC generation id")?;
        if input.cache_id <= 0
            || input.expected_epoch < 0
            || input.expires_at <= input.created_at
            || input.input_versions_digest.is_empty()
            || input.manifest_digest.is_empty()
            || input.actor_scope_digest.is_empty()
            || input.confirmation_hash.is_empty()
            || input.created_by.trim().is_empty()
            || input.request_idempotency_key.is_empty()
            || input.request_digest.is_empty()
        {
            bail!("cache GC plan identity, versions, digests, or lifetime are invalid");
        }
        if !input
            .objects
            .windows(2)
            .all(|pair| pair[0].cache_object_id < pair[1].cache_object_id)
            || !input
                .actions
                .windows(2)
                .all(|pair| pair[0].action_id < pair[1].action_id)
            || !input.object_actions.windows(2).all(|pair| {
                (&pair[0].cache_object_id, &pair[0].action_id)
                    < (&pair[1].cache_object_id, &pair[1].action_id)
            })
            || !input.dependencies.windows(2).all(|pair| {
                (&pair[0].action_id, &pair[0].prerequisite_action_id)
                    < (&pair[1].action_id, &pair[1].prerequisite_action_id)
            })
        {
            bail!("cache GC plan manifests must be strictly canonically ordered");
        }
        let generation = self
            .backend
            .query_opt(
                "SELECT expected_epoch, root_generation,
                   object_graph_generation, inventory_generation,
                   gc_policy_version, topology_version, root_count,
                   marked_object_count, coverage_error_count,
                   parent_mark_generation_id
                 FROM cache_gc_generations
                 WHERE cache_id = ?1 AND generation_id = ?2
                   AND state = 'complete'",
                &vals![input.cache_id, input.generation_id],
            )
            .await?
            .context("cache GC plan requires a complete mark generation")?;
        let topology_snapshot_digest = self
            .cache_gc_generation_topology_digest(input.cache_id, &input.generation_id)
            .await?;
        let derived_input_versions_digest = digest_text(&format!(
            "cache={};epoch={};roots={};graph={};inventory={};policy={};topology={};topology_snapshot={};root_count={};mark_count={};coverage_errors={};parent_mark={:?}",
            input.cache_id,
            generation.get::<i64>(0)?,
            generation.get::<i64>(1)?,
            generation.get::<i64>(2)?,
            generation.get::<i64>(3)?,
            generation.get::<i64>(4)?,
            generation.get::<i64>(5)?,
            topology_snapshot_digest,
            generation.get::<i64>(6)?,
            generation.get::<i64>(7)?,
            generation.get::<i64>(8)?,
            generation.get::<Option<String>>(9)?,
        ));
        let derived_manifest_digest = cache_gc_manifest_digest(input)?;
        let derived_confirmation_hash = digest_text(&format!(
            "plan={};inputs={};manifest={};actor_scope={};expires_at={}",
            input.plan_id,
            derived_input_versions_digest,
            derived_manifest_digest,
            input.actor_scope_digest,
            input.expires_at
        ));
        if input.input_versions_digest != derived_input_versions_digest
            || input.manifest_digest != derived_manifest_digest
            || input.confirmation_hash != derived_confirmation_hash
        {
            bail!("cache GC plan digests do not match their canonical relational inputs");
        }
        let mut statements = vec![Statement::new(
            "INSERT INTO cache_gc_plans
                 (plan_id, cache_id, generation_id, expected_epoch,
                  input_versions_digest, manifest_digest, actor_scope_digest,
                  confirmation_hash, created_by, request_idempotency_key,
                  request_digest, created_at, expires_at)
                 SELECT ?1, generation.cache_id, generation.generation_id,
                        generation.expected_epoch, ?5, ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13
                 FROM cache_gc_generations generation
                 JOIN cache_gc_state state ON state.cache_id = generation.cache_id
                 JOIN cache_gc_heads head ON head.cache_id = state.cache_id
                 WHERE generation.cache_id = ?2 AND generation.generation_id = ?3
                   AND generation.state = 'complete'
                   AND generation.coverage_error_count = 0
                   AND generation.expected_epoch = ?4
                   AND state.epoch = ?4
                   AND head.current_mark_generation_id = generation.generation_id",
            vals![
                input.plan_id,
                input.cache_id,
                input.generation_id,
                input.expected_epoch,
                input.input_versions_digest,
                input.manifest_digest,
                input.actor_scope_digest,
                input.confirmation_hash,
                input.created_by,
                input.request_idempotency_key,
                input.request_digest,
                input.created_at,
                input.expires_at
            ],
        )
        .expecting(1)];
        for object in &input.objects {
            if object.cache_object_id <= 0
                || object.expected_object_version <= 0
                || object.expected_unreferenced_since < 0
                || object.logical_bytes < 0
                || !matches!(
                    object.eligibility_reason.as_str(),
                    "ttl" | "byte_cap" | "object_cap"
                )
            {
                bail!("cache GC candidate is malformed");
            }
            validate_store_hash(&object.store_hash)?;
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_plan_objects
                     (cache_id, plan_id, cache_object_id, store_hash,
                      expected_object_version, expected_unreferenced_since,
                      eligibility_reason, logical_bytes)
                     SELECT ?1, ?2, object.id, object.store_hash, ?5, ?6, ?7, ?8
                     FROM cache_objects object
                     JOIN cache_gc_policies policy ON policy.cache_id = object.cache_id
                     WHERE object.cache_id = ?1 AND object.id = ?3
                       AND object.store_hash = ?4
                       AND object.lifecycle_state = 'active'
                       AND object.resource_version = ?5
                       AND object.unreferenced_since = ?6
                       AND object.file_size = ?8
                       AND object.unreferenced_since
                         + policy.unreferenced_grace_secs <= ?9
                       AND ((?7 = 'ttl')
                         OR (?7 = 'byte_cap' AND policy.soft_max_bytes IS NOT NULL
                           AND (SELECT COALESCE(SUM(active.file_size), 0)
                             FROM cache_objects active
                             WHERE active.cache_id = ?1
                               AND active.lifecycle_state = 'active')
                             > policy.soft_max_bytes)
                         OR (?7 = 'object_cap' AND policy.soft_max_objects IS NOT NULL
                           AND (SELECT COUNT(*) FROM cache_objects active
                             WHERE active.cache_id = ?1
                               AND active.lifecycle_state = 'active')
                             > policy.soft_max_objects))
                       AND NOT EXISTS (SELECT 1 FROM cache_gc_marks mark
                         JOIN cache_gc_plans plan ON plan.generation_id = mark.generation_id
                           AND plan.cache_id = mark.cache_id
                         WHERE plan.cache_id = ?1 AND plan.plan_id = ?2
                           AND mark.cache_object_id = object.id)",
                    vals![
                        input.cache_id,
                        input.plan_id,
                        object.cache_object_id,
                        object.store_hash,
                        object.expected_object_version,
                        object.expected_unreferenced_since,
                        object.eligibility_reason,
                        object.logical_bytes,
                        input.created_at
                    ],
                )
                .expecting(1),
            );
        }
        for action in &input.actions {
            validate_stable_key(&action.action_id, "cache GC action id")?;
            if !matches!(action.phase.as_str(), "narinfo" | "nar")
                || action.surface_object_id <= 0
                || action.placement_id <= 0
                || action.expected_inventory_generation <= 0
                || action.binding_id <= 0
                || action.binding_resource_version <= 0
                || action.delete_credential_generation <= 0
                || action.expected_size.is_some_and(|size| size < 0)
                || action.estimated_reclaimable_bytes < 0
            {
                bail!("cache GC physical action is malformed");
            }
            crate::surface_write::strong_if_match_etag(
                action
                    .expected_etag
                    .as_deref()
                    .context("cache GC physical action requires a strong ETag")?,
            )?;
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_plan_actions
                     (action_id, cache_id, plan_id, surface_object_id,
                      placement_id, phase, expected_etag, expected_hash,
                      expected_size, expected_inventory_generation,
                      binding_id, binding_resource_version,
                      delete_credential_generation, estimated_reclaimable_bytes)
                     SELECT ?3, ?1, ?2, presence.surface_object_id,
                            presence.placement_id, ?6, ?7, ?8, ?9, ?10,
                            ?11, ?12, ?13, ?14
                     FROM object_placements presence
                     JOIN cache_gc_state state ON state.cache_id = presence.cache_id
                     JOIN surface_placements placement
                       ON placement.id = presence.placement_id
                      AND placement.cache_id = presence.cache_id
                     JOIN bindings binding
                       ON binding.id = placement.binding_id
                     JOIN cache_inventory_placement_scans scan
                       ON scan.cache_id = presence.cache_id
                      AND scan.placement_id = presence.placement_id
                      AND scan.generation = presence.observed_inventory_generation
                     JOIN binding_credential_revisions credential
                       ON credential.binding_id = binding.id
                      AND credential.purpose = 'delete'
                      AND credential.generation = ?13
                     WHERE presence.cache_id = ?1
                       AND presence.surface_object_id = ?4
                       AND presence.placement_id = ?5
                       AND (presence.state IN ('present', 'corrupt') OR (
                         presence.state = 'deleting' AND EXISTS (
                           SELECT 1 FROM object_deletion_jobs existing
                           WHERE existing.surface_object_id = presence.surface_object_id
                             AND existing.placement_id = presence.placement_id
                             AND existing.cache_id = presence.cache_id
                             AND existing.active_slot = 1
                             AND existing.phase = ?6
                             AND (existing.expected_etag = ?7
                               OR (existing.expected_etag IS NULL AND ?7 IS NULL))
                             AND (existing.expected_hash = ?8
                               OR (existing.expected_hash IS NULL AND ?8 IS NULL))
                             AND (existing.expected_size = ?9
                               OR (existing.expected_size IS NULL AND ?9 IS NULL))
                             AND existing.expected_inventory_generation = ?10)))
                       AND presence.observed_inventory_generation = ?10
                       AND state.inventory_generation = ?10
                       AND scan.completed_at IS NOT NULL
                       AND scan.binding_id = ?11
                       AND scan.binding_resource_version = ?12
                       AND placement.binding_id = ?11
                       AND binding.resource_version = ?12
                       AND credential.validation_state = 'valid'
                       AND EXISTS (SELECT 1
                         FROM binding_credential_heads credential_head
                         WHERE credential_head.binding_id = ?11
                           AND credential_head.purpose = 'delete'
                           AND credential_head.current_generation = ?13)
                       AND (presence.etag = ?7
                         OR (presence.etag IS NULL AND ?7 IS NULL))
                       AND (presence.observed_hash = ?8
                         OR (presence.observed_hash IS NULL AND ?8 IS NULL))
                       AND (presence.observed_size = ?9
                         OR (presence.observed_size IS NULL AND ?9 IS NULL))",
                    vals![
                        input.cache_id,
                        input.plan_id,
                        action.action_id,
                        action.surface_object_id,
                        action.placement_id,
                        action.phase,
                        action.expected_etag,
                        action.expected_hash,
                        action.expected_size,
                        action.expected_inventory_generation,
                        action.binding_id,
                        action.binding_resource_version,
                        action.delete_credential_generation,
                        action.estimated_reclaimable_bytes
                    ],
                )
                .expecting(1),
            );
        }
        for link in &input.object_actions {
            validate_stable_key(&link.action_id, "cache GC action id")?;
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_plan_object_actions
                     (cache_id, plan_id, cache_object_id, action_id)
                     SELECT ?1, ?2, ?3, ?4
                     WHERE EXISTS (SELECT 1 FROM cache_gc_plan_objects
                       WHERE cache_id = ?1 AND plan_id = ?2
                         AND cache_object_id = ?3)
                       AND EXISTS (SELECT 1 FROM cache_gc_plan_actions
                         WHERE cache_id = ?1 AND plan_id = ?2 AND action_id = ?4)",
                    vals![
                        input.cache_id,
                        input.plan_id,
                        link.cache_object_id,
                        link.action_id
                    ],
                )
                .expecting(1),
            );
        }
        for dependency in &input.dependencies {
            validate_stable_key(&dependency.action_id, "cache GC action id")?;
            validate_stable_key(
                &dependency.prerequisite_action_id,
                "cache GC prerequisite action id",
            )?;
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_action_dependencies
                     (cache_id, plan_id, action_id, prerequisite_action_id)
                     SELECT ?1, ?2, dependent.action_id, prerequisite.action_id
                     FROM cache_gc_plan_actions dependent
                     JOIN cache_gc_plan_actions prerequisite
                       ON prerequisite.cache_id = dependent.cache_id
                      AND prerequisite.plan_id = dependent.plan_id
                      AND prerequisite.placement_id = dependent.placement_id
                     WHERE dependent.cache_id = ?1 AND dependent.plan_id = ?2
                       AND dependent.action_id = ?3 AND dependent.phase = 'nar'
                       AND prerequisite.action_id = ?4
                       AND prerequisite.phase = 'narinfo'",
                    vals![
                        input.cache_id,
                        input.plan_id,
                        dependency.action_id,
                        dependency.prerequisite_action_id
                    ],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "INSERT INTO cache_gc_plan_build_assertions
                 (cache_id, plan_id, ok, asserted_at)
                 VALUES (?1, ?2, CASE WHEN
                   (SELECT COUNT(*) FROM cache_gc_plan_objects
                     WHERE cache_id = ?1 AND plan_id = ?2) = ?3
                   AND (SELECT COUNT(*) FROM cache_gc_plan_actions
                     WHERE cache_id = ?1 AND plan_id = ?2) = ?4
                   AND (SELECT COUNT(*) FROM cache_gc_plan_object_actions
                     WHERE cache_id = ?1 AND plan_id = ?2) = ?5
                   AND (SELECT COUNT(*) FROM cache_gc_action_dependencies
                     WHERE cache_id = ?1 AND plan_id = ?2) = ?6
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_policies policy
                     WHERE policy.cache_id = ?1
                       AND policy.soft_max_bytes IS NOT NULL
                       AND (SELECT COALESCE(SUM(object.file_size), 0)
                         FROM cache_objects object
                         WHERE object.cache_id = ?1
                           AND object.lifecycle_state = 'active')
                         > policy.soft_max_bytes
                       AND (SELECT COALESCE(SUM(object.file_size), 0)
                         FROM cache_objects object
                         WHERE object.cache_id = ?1
                           AND object.lifecycle_state = 'active')
                         - (SELECT COALESCE(SUM(candidate.logical_bytes), 0)
                           FROM cache_gc_plan_objects candidate
                           WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2)
                         > policy.soft_max_bytes)
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_policies policy
                     WHERE policy.cache_id = ?1
                       AND policy.soft_max_objects IS NOT NULL
                       AND (SELECT COUNT(*) FROM cache_objects object
                         WHERE object.cache_id = ?1
                           AND object.lifecycle_state = 'active')
                         > policy.soft_max_objects
                       AND (SELECT COUNT(*) FROM cache_objects object
                         WHERE object.cache_id = ?1
                           AND object.lifecycle_state = 'active')
                         - (SELECT COUNT(*) FROM cache_gc_plan_objects candidate
                           WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2)
                         > policy.soft_max_objects)
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_actions action
                     WHERE action.cache_id = ?1 AND action.plan_id = ?2
                       AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_object_actions link
                         WHERE link.cache_id = ?1 AND link.plan_id = ?2
                           AND link.action_id = action.action_id))
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_object_actions link
                     JOIN cache_gc_plan_actions action
                       ON action.action_id = link.action_id
                      AND action.cache_id = link.cache_id
                      AND action.plan_id = link.plan_id
                     JOIN cache_objects object ON object.id = link.cache_object_id
                       AND object.cache_id = link.cache_id
                     WHERE link.cache_id = ?1 AND link.plan_id = ?2
                       AND ((action.phase = 'narinfo'
                         AND action.surface_object_id <> object.narinfo_surface_object_id)
                         OR (action.phase = 'nar'
                           AND action.surface_object_id <> object.nar_surface_object_id)))
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_actions action
                     WHERE action.cache_id = ?1 AND action.plan_id = ?2
                       AND action.phase = 'nar'
                       AND EXISTS (SELECT 1 FROM cache_objects live
                         WHERE live.cache_id = action.cache_id
                           AND live.nar_surface_object_id = action.surface_object_id
                           AND live.lifecycle_state = 'active'
                           AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_objects candidate
                             WHERE candidate.cache_id = live.cache_id
                               AND candidate.plan_id = action.plan_id
                               AND candidate.cache_object_id = live.id)))
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_object_actions nar_link
                     JOIN cache_gc_plan_actions nar_action
                       ON nar_action.action_id = nar_link.action_id
                      AND nar_action.cache_id = nar_link.cache_id
                      AND nar_action.plan_id = nar_link.plan_id
                     JOIN cache_gc_plan_object_actions narinfo_link
                       ON narinfo_link.cache_id = nar_link.cache_id
                      AND narinfo_link.plan_id = nar_link.plan_id
                      AND narinfo_link.cache_object_id = nar_link.cache_object_id
                     JOIN cache_gc_plan_actions narinfo_action
                       ON narinfo_action.action_id = narinfo_link.action_id
                      AND narinfo_action.cache_id = narinfo_link.cache_id
                      AND narinfo_action.plan_id = narinfo_link.plan_id
                      AND narinfo_action.phase = 'narinfo'
                      AND narinfo_action.placement_id = nar_action.placement_id
                     WHERE nar_link.cache_id = ?1 AND nar_link.plan_id = ?2
                       AND nar_action.phase = 'nar'
                       AND NOT EXISTS (SELECT 1 FROM cache_gc_action_dependencies dependency
                         WHERE dependency.cache_id = ?1 AND dependency.plan_id = ?2
                           AND dependency.action_id = nar_action.action_id
                           AND dependency.prerequisite_action_id
                             = narinfo_action.action_id))
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_objects candidate
                   JOIN cache_objects object ON object.id = candidate.cache_object_id
                       AND object.cache_id = candidate.cache_id
                     JOIN object_placements presence ON presence.cache_id = object.cache_id
                       AND presence.state <> 'missing'
                       AND (presence.surface_object_id = object.narinfo_surface_object_id
                         OR (presence.surface_object_id = object.nar_surface_object_id
                           AND NOT EXISTS (SELECT 1 FROM cache_objects live
                             WHERE live.cache_id = object.cache_id
                               AND live.nar_surface_object_id = object.nar_surface_object_id
                               AND live.lifecycle_state = 'active'
                               AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_objects
                                 WHERE cache_id = live.cache_id AND plan_id = ?2
                                   AND cache_object_id = live.id))))
                     WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2
                       AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_object_actions link
                         JOIN cache_gc_plan_actions action
                           ON action.action_id = link.action_id
                          AND action.cache_id = link.cache_id
                          AND action.plan_id = link.plan_id
                         WHERE link.cache_id = ?1 AND link.plan_id = ?2
                           AND link.cache_object_id = object.id
                           AND action.surface_object_id = presence.surface_object_id
                           AND action.placement_id = presence.placement_id))
                 THEN 1 ELSE 0 END, ?7)",
                vals![
                    input.cache_id,
                    input.plan_id,
                    i64::try_from(input.objects.len())
                        .context("cache GC object count exceeds i64")?,
                    i64::try_from(input.actions.len())
                        .context("cache GC action count exceeds i64")?,
                    i64::try_from(input.object_actions.len())
                        .context("cache GC object-action count exceeds i64")?,
                    i64::try_from(input.dependencies.len())
                        .context("cache GC dependency count exceeds i64")?,
                    input.created_at
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await
    }

    async fn assert_cache_gc_delete_topology_supported(&self, cache_id: i64) -> Result<()> {
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM surface_placements placement
             JOIN bindings binding ON binding.id = placement.binding_id
             WHERE placement.cache_id = ?1
               AND binding.kind IN ('r2', 'deployment_r2') LIMIT 1",
                &vals![cache_id],
            )
            .await?
            .is_some()
        {
            bail!(
                "destructive GC is unsupported for R2 placements without strong conditional delete"
            );
        }
        Ok(())
    }

    /// Begins an unreachable mark generation from one exact cache-state snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, absent policy/state, a stale epoch,
    /// duplicate identity, or database failure.
    pub async fn begin_cache_gc_generation(&self, input: &BeginCacheGcGeneration) -> Result<()> {
        validate_stable_key(&input.generation_id, "cache GC generation id")?;
        if input.cache_id <= 0 || input.expected_epoch < 0 {
            bail!("cache GC generation has invalid cache or epoch");
        }
        let statements = vec![
            Statement::new(
                "INSERT INTO cache_gc_generations
             (generation_id, cache_id, state, cutoff_at, expected_epoch,
              root_generation, object_graph_generation, inventory_generation,
              gc_policy_version, topology_version, parent_mark_generation_id,
              root_count,
              marked_object_count, coverage_error_count, created_at)
             SELECT ?1, state.cache_id, 'building', ?3, state.epoch,
                    state.root_generation, state.object_graph_generation,
                    state.inventory_generation, policy.resource_version,
                    state.topology_generation, head.current_mark_generation_id,
                    0, 0, 0, ?5
             FROM cache_gc_state state
             JOIN cache_gc_policies policy ON policy.cache_id = state.cache_id
             JOIN cache_gc_heads head ON head.cache_id = state.cache_id
             JOIN cache_inventory_generations inventory
               ON inventory.cache_id = state.cache_id
              AND inventory.generation = state.inventory_generation
             WHERE state.cache_id = ?2 AND state.epoch = ?4
               AND inventory.state = 'published'
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 WHERE ticket.cache_id = state.cache_id AND (
                   ticket.active_cache_slot = 1 OR
                   (ticket.state = 'completed'
                     AND ticket.covered_inventory_generation IS NULL)))",
                vals![
                    input.generation_id,
                    input.cache_id,
                    input.cutoff_at,
                    input.expected_epoch,
                    input.created_at
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_generation_roots
             (cache_id, generation_id, root_reason_id, store_hash)
             WITH RECURSIVE active_refreshes(refresh_id, subscription_id) AS (
               SELECT head.current_refresh_id, subscription.id
               FROM cache_retention_subscriptions subscription
               JOIN cache_retention_refresh_heads head
                 ON head.subscription_id = subscription.id
               JOIN cache_gc_generations generation
                 ON generation.cache_id = subscription.cache_id
                AND generation.generation_id = ?2
               WHERE subscription.cache_id = ?1
                 AND ((subscription.enabled = 1
                       AND subscription.retired_at IS NULL)
                   OR (subscription.retired_at IS NOT NULL
                     AND subscription.retired_at
                       + subscription.removal_grace_secs > generation.cutoff_at))
               UNION ALL
               SELECT parent.refresh_id, parent.subscription_id
               FROM active_refreshes active
               JOIN cache_retention_refreshes child
                 ON child.refresh_id = active.refresh_id
               JOIN cache_retention_refreshes parent
                 ON parent.refresh_id = child.parent_refresh_id
               JOIN cache_gc_generations generation
                 ON generation.cache_id = parent.cache_id
                AND generation.generation_id = ?2
               WHERE child.parent_grace_until > generation.cutoff_at
                 AND parent.state = 'complete'
             )
             SELECT reason.cache_id, ?2, reason.id, reason.store_hash
             FROM cache_root_reasons reason
             JOIN cache_gc_generations generation
               ON generation.cache_id = reason.cache_id
              AND generation.generation_id = ?2
             LEFT JOIN manual_retention_roots root
               ON root.id = reason.manual_retention_root_id
             LEFT JOIN retention_leases lease
               ON lease.id = reason.retention_lease_id
             LEFT JOIN manual_retention_lease_heads lease_head
               ON lease_head.manual_retention_root_id = root.id
             WHERE reason.cache_id = ?1
               AND (reason.expires_at IS NULL
                 OR reason.expires_at > generation.cutoff_at)
               AND ((reason.refresh_id IS NOT NULL AND EXISTS (
                     SELECT 1 FROM active_refreshes active
                     WHERE active.refresh_id = reason.refresh_id))
                 OR (reason.source_kind = 'manual' AND root.deleted_at IS NULL
                   AND root.protection_kind = 'indefinite')
                 OR (reason.source_kind = 'lease' AND root.deleted_at IS NULL
                   AND root.protection_kind = 'leased'
                   AND lease_head.current_lease_id = lease.id
                   AND lease.state = 'active'
                   AND lease.begins_at <= generation.cutoff_at
                   AND lease.expires_at > generation.cutoff_at))",
                vals![input.cache_id, input.generation_id],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_gc_generation_placements
                 (cache_id, generation_id, placement_id,
                  placement_resource_version, placement_name,
                  binding_id, binding_stable_id,
                  binding_resource_version, prefix, placement_kind,
                  desired_state, write_spec_version,
                  requires_conditional_writes)
                 SELECT placement.cache_id, ?2, placement.id,
                        placement.resource_version, placement.name,
                        binding.id, COALESCE(binding.stable_id, ''),
                        binding.resource_version, placement.prefix,
                        placement.kind, placement.desired_state,
                        placement.write_spec_version,
                        placement.requires_conditional_writes
                 FROM surface_placements placement
                 JOIN bindings binding
                   ON binding.id = placement.binding_id
                 JOIN cache_gc_generations generation
                   ON generation.cache_id = placement.cache_id
                  AND generation.generation_id = ?2
                 WHERE placement.cache_id = ?1",
                vals![input.cache_id, input.generation_id],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Stages one closure object under a building mark generation.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/cross-cache/tombstoned object, a terminal
    /// generation, duplicate identity, or database failure.
    pub async fn stage_cache_gc_mark(
        &self,
        cache_id: i64,
        generation_id: &str,
        cache_object_id: i64,
    ) -> Result<()> {
        validate_stable_key(generation_id, "cache GC generation id")?;
        let statement = Statement::new(
            "INSERT INTO cache_gc_marks
             (cache_id, generation_id, cache_object_id)
             SELECT generation.cache_id, generation.generation_id, object.id
             FROM cache_gc_generations generation
             JOIN cache_objects object ON object.id = ?3
               AND object.cache_id = generation.cache_id
             WHERE generation.cache_id = ?1 AND generation.generation_id = ?2
               AND generation.state = 'building'
               AND object.lifecycle_state = 'active'",
            vals![cache_id, generation_id, cache_object_id],
        )
        .expecting(1);
        self.backend.checked_batch(&[statement]).await
    }

    /// Stages one explicit coverage failure without stopping other closure walks.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a terminal generation, duplicate
    /// identity, or database failure.
    pub async fn stage_cache_gc_coverage_error(
        &self,
        cache_id: i64,
        generation_id: &str,
        error: &CacheGcCoverageError,
    ) -> Result<()> {
        validate_stable_key(generation_id, "cache GC generation id")?;
        validate_stable_key(&error.error_id, "cache GC coverage error id")?;
        if !matches!(
            error.kind.as_str(),
            "missing_root" | "missing_reference" | "stale_inventory"
        ) || error.detail.trim().is_empty()
        {
            bail!("cache GC coverage error kind or detail is invalid");
        }
        if let Some(store_hash) = error.store_hash.as_deref() {
            validate_store_hash(store_hash)?;
        }
        if let Some(store_hash) = error.referenced_store_hash.as_deref() {
            validate_store_hash(store_hash)?;
        }
        let statement = Statement::new(
            "INSERT INTO cache_gc_generation_coverage_errors
             (cache_id, generation_id, error_id, kind, store_hash,
              referenced_store_hash, detail)
             SELECT cache_id, generation_id, ?3, ?4, ?5, ?6, ?7
             FROM cache_gc_generations
             WHERE cache_id = ?1 AND generation_id = ?2 AND state = 'building'",
            vals![
                cache_id,
                generation_id,
                error.error_id,
                error.kind,
                error.store_hash,
                error.referenced_store_hash,
                error.detail
            ],
        )
        .expecting(1);
        self.backend.checked_batch(&[statement]).await
    }

    /// Publishes a mark generation if its captured cache inputs remain current.
    ///
    /// Coverage failures remain attached and make destructive plan apply
    /// impossible. Unmarked objects receive their first-unreferenced time once;
    /// marked objects clear it.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale epoch/input generation, a terminal mark, or
    /// database failure.
    pub async fn complete_cache_gc_generation(
        &self,
        cache_id: i64,
        generation_id: &str,
        completed_at: i64,
    ) -> Result<()> {
        validate_stable_key(generation_id, "cache GC generation id")?;
        let statements = vec![
            Statement::new(
                "UPDATE cache_gc_generations SET state = 'complete',
                   scanned_object_count = (SELECT COUNT(*) FROM cache_objects
                     WHERE cache_id = ?1 AND lifecycle_state = 'active'),
                   root_count = (SELECT COUNT(*) FROM cache_gc_generation_roots
                     WHERE cache_id = ?1 AND generation_id = ?2),
                   marked_object_count = (SELECT COUNT(*) FROM cache_gc_marks
                     WHERE cache_id = ?1 AND generation_id = ?2),
                   coverage_error_count = (SELECT COUNT(*)
                     FROM cache_gc_generation_coverage_errors
                     WHERE cache_id = ?1 AND generation_id = ?2),
                   completed_at = ?3
                 WHERE cache_id = ?1 AND generation_id = ?2 AND state = 'building'
                   AND EXISTS (SELECT 1 FROM cache_gc_state state
                     JOIN cache_gc_policies policy ON policy.cache_id = state.cache_id
                     WHERE state.cache_id = ?1
                       AND state.epoch = expected_epoch
                       AND state.root_generation = root_generation
                       AND state.object_graph_generation = object_graph_generation
                       AND state.inventory_generation = inventory_generation
                       AND state.topology_generation = topology_version
                       AND policy.resource_version = gc_policy_version)
                   AND NOT EXISTS (SELECT 1
                     FROM cache_gc_generation_coverage_errors coverage
                     WHERE coverage.cache_id = ?1
                       AND coverage.generation_id = ?2)
                   AND NOT EXISTS (SELECT 1
                     FROM cache_object_mutation_fences fence
                     WHERE fence.cache_id = ?1 AND fence.state = 'active')
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_retention_subscriptions subscription
                     LEFT JOIN registry_index registry
                       ON registry.registry_id = subscription.registry_id
                     LEFT JOIN cache_retention_refresh_heads refresh_head
                       ON refresh_head.subscription_id = subscription.id
                     LEFT JOIN cache_retention_refreshes refresh
                       ON refresh.refresh_id = refresh_head.current_refresh_id
                      AND refresh.subscription_id = subscription.id
                     WHERE subscription.cache_id = ?1
                       AND subscription.enabled = 1
                       AND subscription.retired_at IS NULL
                       AND (subscription.refresh_state <> 'fresh'
                         OR subscription.last_successful_revision IS NULL
                         OR registry.state <> 'fresh'
                         OR registry.last_indexed_commit IS NULL
                         OR subscription.last_successful_revision
                           <> registry.last_indexed_commit
                         OR refresh.refresh_id IS NULL
                         OR refresh.state <> 'complete'
                         OR refresh.registry_source_revision
                           <> registry.last_indexed_commit
                         OR refresh.registry_index_generation <> registry.generation
                         OR refresh.registry_index_digest <> registry.content_digest))
                   AND NOT EXISTS (SELECT 1
                     FROM cache_gc_generation_placements captured
                     LEFT JOIN surface_placements placement
                       ON placement.id = captured.placement_id
                      AND placement.cache_id = captured.cache_id
                     LEFT JOIN bindings binding
                       ON binding.id = placement.binding_id
                     WHERE captured.cache_id = ?1
                       AND captured.generation_id = ?2
                       AND (placement.id IS NULL
                         OR placement.resource_version
                           <> captured.placement_resource_version
                         OR placement.name <> captured.placement_name
                         OR placement.binding_id
                           <> captured.binding_id
                         OR COALESCE(binding.stable_id, '')
                           <> captured.binding_stable_id
                         OR binding.resource_version
                           <> captured.binding_resource_version
                         OR placement.prefix <> captured.prefix
                         OR placement.kind <> captured.placement_kind
                         OR placement.desired_state <> captured.desired_state
                         OR placement.write_spec_version
                           <> captured.write_spec_version
                         OR placement.requires_conditional_writes
                           <> captured.requires_conditional_writes))
                   AND NOT EXISTS (SELECT 1 FROM surface_placements placement
                     WHERE placement.cache_id = ?1
                       AND NOT EXISTS (SELECT 1
                         FROM cache_gc_generation_placements captured
                         WHERE captured.cache_id = ?1
                           AND captured.generation_id = ?2
                           AND captured.placement_id = placement.id))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_gc_generation_roots root
                     LEFT JOIN cache_objects object
                       ON object.cache_id = root.cache_id
                      AND object.store_hash = root.store_hash
                      AND object.lifecycle_state = 'active'
                     LEFT JOIN cache_gc_marks mark
                       ON mark.cache_id = root.cache_id
                      AND mark.generation_id = root.generation_id
                      AND mark.cache_object_id = object.id
                     WHERE root.cache_id = ?1 AND root.generation_id = ?2
                       AND (object.id IS NULL OR mark.cache_object_id IS NULL))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_gc_marks mark
                     JOIN cache_objects object ON object.id = mark.cache_object_id
                       AND object.cache_id = mark.cache_id
                     WHERE mark.cache_id = ?1 AND mark.generation_id = ?2
                       AND object.reference_count <> (SELECT COUNT(*)
                         FROM cache_object_references edge
                         WHERE edge.cache_id = object.cache_id
                           AND edge.cache_object_id = object.id))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_gc_marks mark
                     JOIN cache_object_references edge
                       ON edge.cache_id = mark.cache_id
                      AND edge.cache_object_id = mark.cache_object_id
                     LEFT JOIN cache_objects referenced
                       ON referenced.id = edge.referenced_cache_object_id
                      AND referenced.cache_id = edge.cache_id
                      AND referenced.lifecycle_state = 'active'
                     LEFT JOIN cache_gc_marks referenced_mark
                       ON referenced_mark.cache_id = edge.cache_id
                      AND referenced_mark.generation_id = mark.generation_id
                      AND referenced_mark.cache_object_id = referenced.id
                     WHERE mark.cache_id = ?1 AND mark.generation_id = ?2
                       AND (referenced.id IS NULL
                         OR referenced_mark.cache_object_id IS NULL))",
                vals![cache_id, generation_id, completed_at],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_objects SET unreferenced_since = COALESCE(
                     unreferenced_since, (SELECT cutoff_at FROM cache_gc_generations
                       WHERE cache_id = ?1 AND generation_id = ?2)),
                   resource_version = CASE WHEN unreferenced_since IS NULL
                     THEN resource_version + 1 ELSE resource_version END
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_marks mark
                     WHERE mark.cache_id = ?1 AND mark.generation_id = ?2
                       AND mark.cache_object_id = cache_objects.id)",
                vals![cache_id, generation_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_objects SET unreferenced_since = NULL,
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND unreferenced_since IS NOT NULL
                   AND EXISTS (SELECT 1 FROM cache_gc_marks mark
                     WHERE mark.cache_id = ?1 AND mark.generation_id = ?2
                       AND mark.cache_object_id = cache_objects.id)",
                vals![cache_id, generation_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_gc_heads SET current_mark_generation_id = ?2,
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1
                   AND (current_mark_generation_id = (SELECT parent_mark_generation_id
                         FROM cache_gc_generations
                         WHERE cache_id = ?1 AND generation_id = ?2)
                     OR (current_mark_generation_id IS NULL
                       AND (SELECT parent_mark_generation_id
                         FROM cache_gc_generations
                         WHERE cache_id = ?1 AND generation_id = ?2) IS NULL))
                   AND EXISTS (SELECT 1 FROM cache_gc_state state
                     JOIN cache_gc_generations generation
                       ON generation.cache_id = state.cache_id
                      AND generation.generation_id = ?2
                     WHERE state.cache_id = ?1 AND generation.state = 'complete'
                       AND state.epoch = generation.expected_epoch)",
                vals![cache_id, generation_id],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Terminates an incomplete mark generation without publishing eligibility.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty detail, a missing/terminal generation, or
    /// database failure.
    pub async fn fail_cache_gc_generation(
        &self,
        cache_id: i64,
        generation_id: &str,
        error: &str,
        failed_at: i64,
    ) -> Result<()> {
        validate_stable_key(generation_id, "cache GC generation id")?;
        if error.trim().is_empty() {
            bail!("failed cache GC generation requires an error detail");
        }
        let statement = Statement::new(
            "UPDATE cache_gc_generations SET state = 'failed', error = ?3,
               root_count = (SELECT COUNT(*) FROM cache_gc_generation_roots
                 WHERE cache_id = ?1 AND generation_id = ?2),
               marked_object_count = (SELECT COUNT(*) FROM cache_gc_marks
                 WHERE cache_id = ?1 AND generation_id = ?2),
               coverage_error_count = (SELECT COUNT(*)
                 FROM cache_gc_generation_coverage_errors
                 WHERE cache_id = ?1 AND generation_id = ?2),
               completed_at = ?4
             WHERE cache_id = ?1 AND generation_id = ?2 AND state = 'building'",
            vals![cache_id, generation_id, error, failed_at],
        )
        .expecting(1);
        self.backend.checked_batch(&[statement]).await
    }

    /// Begins a cache-object mutation fence and advances the cache epoch.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid vocabulary, a missing operation, a stale
    /// cache epoch, a duplicate active fence, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_cache_object_mutation_fence(
        &self,
        cache_id: i64,
        store_hash: &str,
        operation_id: &str,
        kind: &str,
        expected_epoch: i64,
        mutation_id: &str,
        now: i64,
    ) -> Result<()> {
        validate_store_hash(store_hash)?;
        validate_stable_key(operation_id, "cache object mutation operation id")?;
        validate_stable_key(mutation_id, "cache object fence mutation id")?;
        if !matches!(kind, "upload" | "population" | "replication" | "repair") {
            bail!("invalid cache object mutation-fence kind");
        }
        let statements = vec![
            Statement::new(
                "INSERT INTO cache_object_mutation_fences
                 (cache_id, store_hash, operation_id, operation_target_kind,
                  operation_target_stable_id, kind, state, resource_version)
                 SELECT ?1, ?2, operation.operation_id,
                        operation.primary_target_kind,
                        operation.primary_target_stable_id, ?4, 'active', 1
                 FROM topology_operations operation
                 JOIN binary_caches cache ON cache.id = ?1
                   AND cache.stable_id = operation.primary_target_stable_id
                 WHERE operation.operation_id = ?3
                   AND operation.primary_target_kind = 'binary_cache'
                   AND operation.state IN ('pending', 'running')",
                vals![cache_id, store_hash, operation_id, kind],
            )
            .expecting(1),
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "object_graph_generation = object_graph_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "fence",
                now,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_object_mutation_fences WHERE cache_id = {} AND store_hash = '{}' AND operation_id = '{}' AND state = 'active')",
                    cache_id,
                    sql_literal(store_hash),
                    sql_literal(operation_id)
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Cancels an active cache-object mutation fence and advances the epoch.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale fence/cache epoch, invalid identity, or
    /// database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn cancel_cache_object_mutation_fence(
        &self,
        cache_id: i64,
        store_hash: &str,
        operation_id: &str,
        expected_fence_version: i64,
        expected_epoch: i64,
        mutation_id: &str,
        now: i64,
    ) -> Result<()> {
        validate_store_hash(store_hash)?;
        validate_stable_key(operation_id, "cache object mutation operation id")?;
        validate_stable_key(mutation_id, "cache object fence mutation id")?;
        let statements = vec![
            Statement::new(
                "UPDATE cache_object_mutation_fences
                 SET state = 'cancelled', resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND store_hash = ?2 AND operation_id = ?3
                   AND state = 'active' AND resource_version = ?4",
                vals![cache_id, store_hash, operation_id, expected_fence_version],
            )
            .expecting(1),
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "object_graph_generation = object_graph_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "fence",
                now,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_object_mutation_fences WHERE cache_id = {} AND store_hash = '{}' AND operation_id = '{}' AND state = 'cancelled')",
                    cache_id,
                    sql_literal(store_hash),
                    sql_literal(operation_id)
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Activates normalized cache metadata after narinfo and NAR presence is durable.
    ///
    /// References are inserted as relational edges. Missing referenced objects
    /// remain explicit null targets for coverage reporting; an embedded JSON
    /// reference list is never authoritative.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, absent current placement
    /// presence, a duplicate object, a stale epoch, or database failure.
    pub async fn activate_cache_object_topology(&self, input: &ActivateCacheObject) -> Result<()> {
        validate_store_hash(&input.store_hash)?;
        validate_stable_key(&input.mutation_id, "cache object mutation id")?;
        validate_stable_key(
            &input.mutation_fence_operation_id,
            "cache object mutation-fence operation id",
        )?;
        if input.object_id <= 0
            || input.cache_id <= 0
            || input.narinfo_surface_object_id <= 0
            || input.nar_surface_object_id <= 0
            || input.nar_size < 0
            || input.file_size < 0
            || input.expected_epoch < 0
            || input.expected_fence_version <= 0
            || input.narinfo_surface_object_id == input.nar_surface_object_id
            || input.store_name.is_empty()
            || input.nar_hash.is_empty()
            || input.file_hash.is_empty()
            || input.compression.is_empty()
        {
            bail!("cache object metadata or expected versions are invalid");
        }
        let mut references = input.references.clone();
        references.sort();
        references.dedup();
        if references != input.references {
            bail!("cache object references must be sorted and deduplicated");
        }
        for reference in &references {
            validate_store_hash(reference)?;
        }
        let expected_narinfo_key = format!("{}.narinfo", input.store_hash);
        let mut statements = vec![
            Statement::new(
                "INSERT INTO cache_nar_objects
                 (cache_id, nar_surface_object_id, nar_hash, nar_size,
                  file_hash, file_size, compression, resource_version)
                 SELECT ?1, object.id, ?3, ?4, ?5, ?6, ?7, 1
                 FROM surface_objects object
                 WHERE object.id = ?2 AND object.cache_id = ?1
                   AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?5 AND object.size = ?6
                 ON CONFLICT(cache_id, nar_surface_object_id) DO NOTHING",
                vals![
                    input.cache_id,
                    input.nar_surface_object_id,
                    input.nar_hash,
                    input.nar_size,
                    input.file_hash,
                    input.file_size,
                    input.compression
                ],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_objects
                 (id, cache_id, store_hash, store_name,
                  narinfo_surface_object_id, nar_surface_object_id,
                  nar_hash, nar_size, file_hash, file_size, compression,
                  deriver, signature, content_address, reference_count,
                  lifecycle_state,
                  published_at, resource_version)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                        ?12, ?13, ?14, ?15, 'active', ?16, 1
                 FROM cache_gc_state state
                 JOIN surface_objects narinfo ON narinfo.id = ?5
                   AND narinfo.cache_id = state.cache_id
                 JOIN surface_objects nar ON nar.id = ?6
                   AND nar.cache_id = state.cache_id
                 JOIN cache_nar_objects shared_nar
                   ON shared_nar.cache_id = state.cache_id
                  AND shared_nar.nar_surface_object_id = nar.id
                  AND shared_nar.nar_hash = ?7 AND shared_nar.nar_size = ?8
                  AND shared_nar.file_hash = ?9 AND shared_nar.file_size = ?10
                  AND shared_nar.compression = ?11
                 WHERE state.cache_id = ?2 AND state.epoch = ?17
                   AND narinfo.id <> nar.id
                   AND narinfo.object_kind = 'immutable'
                   AND narinfo.lifecycle_state = 'active'
                   AND narinfo.object_key = ?20
                   AND nar.object_kind = 'immutable'
                   AND nar.lifecycle_state = 'active'
                   AND nar.content_hash = ?9 AND nar.size = ?10
                   AND EXISTS (SELECT 1 FROM cache_object_mutation_fences fence
                     WHERE fence.cache_id = ?2 AND fence.store_hash = ?3
                       AND fence.operation_id = ?18 AND fence.state = 'active'
                       AND fence.resource_version = ?19)
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.cache_id = ?2
                       AND presence.surface_object_id = ?5
                       AND presence.state = 'present'
                       AND presence.observed_hash = narinfo.content_hash
                       AND presence.observed_size = narinfo.size
                       AND presence.observed_inventory_generation
                         = state.inventory_generation)
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.cache_id = ?2
                       AND presence.surface_object_id = ?6
                       AND presence.state = 'present'
                       AND presence.observed_hash = ?9
                       AND presence.observed_size = ?10
                       AND presence.observed_inventory_generation
                         = state.inventory_generation)",
                vals![
                    input.object_id,
                    input.cache_id,
                    input.store_hash,
                    input.store_name,
                    input.narinfo_surface_object_id,
                    input.nar_surface_object_id,
                    input.nar_hash,
                    input.nar_size,
                    input.file_hash,
                    input.file_size,
                    input.compression,
                    input.deriver,
                    input.signature,
                    input.content_address,
                    i64::try_from(references.len())
                        .context("cache object reference count exceeds i64")?,
                    input.published_at,
                    input.expected_epoch,
                    input.mutation_fence_operation_id,
                    input.expected_fence_version,
                    expected_narinfo_key
                ],
            )
            .expecting(1),
        ];
        for reference in &references {
            statements.push(
                Statement::new(
                    "INSERT INTO cache_object_references
                     (cache_id, cache_object_id, referenced_store_hash,
                      referenced_cache_object_id)
                     SELECT ?1, ?2, ?3, referenced.id
                     FROM cache_objects object
                     LEFT JOIN cache_objects referenced
                       ON referenced.cache_id = object.cache_id
                      AND referenced.store_hash = ?3
                      AND referenced.lifecycle_state = 'active'
                     WHERE object.cache_id = ?1 AND object.id = ?2
                       AND object.lifecycle_state = 'active'",
                    vals![input.cache_id, input.object_id, reference],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "UPDATE cache_object_references
                 SET referenced_cache_object_id = ?2
                 WHERE cache_id = ?1 AND referenced_store_hash = ?3
                   AND referenced_cache_object_id IS NULL
                   AND EXISTS (SELECT 1 FROM cache_objects referenced
                     WHERE referenced.cache_id = ?1 AND referenced.id = ?2
                       AND referenced.store_hash = ?3
                       AND referenced.lifecycle_state = 'active')",
                vals![input.cache_id, input.object_id, input.store_hash],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE cache_object_mutation_fences
                 SET state = 'completed', resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND store_hash = ?2 AND operation_id = ?3
                   AND state = 'active' AND resource_version = ?4",
                vals![
                    input.cache_id,
                    input.store_hash,
                    input.mutation_fence_operation_id,
                    input.expected_fence_version
                ],
            )
            .expecting(1),
        );
        statements.push(epoch_update_statement(
            input.cache_id,
            input.expected_epoch,
            &input.mutation_id,
            "object_graph_generation = object_graph_generation + 1",
        ));
        statements.push(epoch_assertion_statement(
            &input.mutation_id,
            input.cache_id,
            input.expected_epoch,
            "object_graph",
            input.published_at,
            &format!(
                "EXISTS (SELECT 1 FROM cache_objects WHERE id = {} AND cache_id = {} AND lifecycle_state = 'active' AND reference_count = {}) AND (SELECT COUNT(*) FROM cache_object_references WHERE cache_id = {} AND cache_object_id = {}) = {} AND EXISTS (SELECT 1 FROM cache_object_mutation_fences WHERE cache_id = {} AND store_hash = '{}' AND operation_id = '{}' AND state = 'completed')",
                input.object_id,
                input.cache_id,
                references.len(),
                input.cache_id,
                input.object_id,
                references.len(),
                input.cache_id,
                sql_literal(&input.store_hash),
                sql_literal(&input.mutation_fence_operation_id)
            ),
        ));
        self.backend.checked_batch(&statements).await
    }

    /// Reactivates an exactly identical tombstoned cache object after repopulation.
    ///
    /// # Errors
    ///
    /// Returns an error unless identity, metadata, normalized references,
    /// current placement evidence, mutation fence, and cache epoch all match.
    pub async fn reactivate_cache_object_topology(
        &self,
        input: &ActivateCacheObject,
    ) -> Result<()> {
        validate_store_hash(&input.store_hash)?;
        validate_stable_key(&input.mutation_id, "cache object reactivation id")?;
        validate_stable_key(
            &input.mutation_fence_operation_id,
            "cache object mutation-fence operation id",
        )?;
        let mut references = input.references.clone();
        references.sort();
        references.dedup();
        if references != input.references {
            bail!("cache object references must be sorted and deduplicated");
        }
        let mut statements = vec![
            Statement::new(
                "UPDATE cache_objects SET lifecycle_state = 'active',
                   tombstoned_at = NULL, unreferenced_since = NULL,
                   published_at = ?15, resource_version = resource_version + 1
                 WHERE id = ?1 AND cache_id = ?2 AND store_hash = ?3
                   AND store_name = ?4 AND narinfo_surface_object_id = ?5
                   AND nar_surface_object_id = ?6 AND ?5 <> ?6
                   AND nar_hash = ?7 AND nar_size = ?8 AND file_hash = ?9
                   AND file_size = ?10 AND compression = ?11
                   AND (deriver = ?12 OR (deriver IS NULL AND ?12 IS NULL))
                   AND (signature = ?13 OR (signature IS NULL AND ?13 IS NULL))
                   AND (content_address = ?14
                     OR (content_address IS NULL AND ?14 IS NULL))
                   AND reference_count = ?16 AND lifecycle_state = 'tombstoned'
                   AND EXISTS (SELECT 1 FROM cache_gc_state state
                     WHERE state.cache_id = ?2 AND state.epoch = ?17)
                   AND EXISTS (SELECT 1 FROM cache_object_mutation_fences fence
                     WHERE fence.cache_id = ?2 AND fence.store_hash = ?3
                       AND fence.operation_id = ?18 AND fence.state = 'active'
                       AND fence.resource_version = ?19)
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.cache_id = ?2
                       AND presence.surface_object_id = ?5
                       AND presence.state = 'present'
                       AND presence.observed_inventory_generation =
                         (SELECT inventory_generation FROM cache_gc_state
                           WHERE cache_id = ?2))
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.cache_id = ?2
                       AND presence.surface_object_id = ?6
                       AND presence.state = 'present'
                       AND presence.observed_inventory_generation =
                         (SELECT inventory_generation FROM cache_gc_state
                           WHERE cache_id = ?2))
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     WHERE job.cache_id = ?2 AND job.active_slot = 1
                       AND (job.surface_object_id = ?5
                         OR job.surface_object_id = ?6))",
                vals![
                    input.object_id,
                    input.cache_id,
                    input.store_hash,
                    input.store_name,
                    input.narinfo_surface_object_id,
                    input.nar_surface_object_id,
                    input.nar_hash,
                    input.nar_size,
                    input.file_hash,
                    input.file_size,
                    input.compression,
                    input.deriver,
                    input.signature,
                    input.content_address,
                    input.published_at,
                    i64::try_from(references.len())
                        .context("cache object reference count exceeds i64")?,
                    input.expected_epoch,
                    input.mutation_fence_operation_id,
                    input.expected_fence_version
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE surface_objects SET lifecycle_state = 'active',
                   tombstoned_at = NULL, updated_at = ?4,
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND id IN (?2, ?3)
                   AND lifecycle_state = 'tombstoned'",
                vals![
                    input.cache_id,
                    input.narinfo_surface_object_id,
                    input.nar_surface_object_id,
                    input.published_at
                ],
            )
            .unchecked(),
        ];
        for reference in &references {
            statements.push(
                Statement::new(
                    "UPDATE cache_object_references
                     SET referenced_cache_object_id = (SELECT id
                       FROM cache_objects referenced
                       WHERE referenced.cache_id = ?1
                         AND referenced.store_hash = ?3
                         AND referenced.lifecycle_state = 'active')
                     WHERE cache_id = ?1 AND cache_object_id = ?2
                       AND referenced_store_hash = ?3",
                    vals![input.cache_id, input.object_id, reference],
                )
                .expecting(1),
            );
        }
        statements.extend([
            Statement::new(
                "UPDATE cache_object_mutation_fences
                 SET state = 'completed', resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND store_hash = ?2 AND operation_id = ?3
                   AND state = 'active' AND resource_version = ?4",
                vals![
                    input.cache_id,
                    input.store_hash,
                    input.mutation_fence_operation_id,
                    input.expected_fence_version
                ],
            )
            .expecting(1),
            epoch_update_statement(
                input.cache_id,
                input.expected_epoch,
                &input.mutation_id,
                "object_graph_generation = object_graph_generation + 1",
            ),
            epoch_assertion_statement(
                &input.mutation_id,
                input.cache_id,
                input.expected_epoch,
                "object_graph",
                input.published_at,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_objects WHERE cache_id = {} AND id = {} AND lifecycle_state = 'active' AND reference_count = (SELECT COUNT(*) FROM cache_object_references WHERE cache_id = {} AND cache_object_id = {}))",
                    input.cache_id, input.object_id, input.cache_id, input.object_id
                ),
            ),
        ]);
        self.backend.checked_batch(&statements).await
    }

    /// Reaps old tombstone metadata only after every physical copy is absent.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale object/cache epoch, a live reference or
    /// deletion job, insufficient tombstone age, residual presence, or
    /// database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn reap_cache_object_tombstone(
        &self,
        cache_id: i64,
        cache_object_id: i64,
        expected_object_version: i64,
        expected_epoch: i64,
        mutation_id: &str,
        reaped_at: i64,
    ) -> Result<()> {
        validate_stable_key(mutation_id, "cache tombstone reap mutation id")?;
        let row = self
            .backend
            .query_opt(
                "SELECT narinfo_surface_object_id, nar_surface_object_id
                 FROM cache_objects
                 WHERE cache_id = ?1 AND id = ?2 AND lifecycle_state = 'tombstoned'",
                &vals![cache_id, cache_object_id],
            )
            .await?
            .context("cache tombstone does not exist")?;
        let narinfo_surface_object_id: i64 = row.get(0)?;
        let nar_surface_object_id: i64 = row.get(1)?;
        let statements = vec![
            Statement::new(
                "DELETE FROM cache_object_references
                 WHERE cache_id = ?1 AND cache_object_id = ?2",
                vals![cache_id, cache_object_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_object_references
                 SET referenced_cache_object_id = NULL
                 WHERE cache_id = ?1 AND referenced_cache_object_id = ?2
                   AND EXISTS (SELECT 1 FROM cache_objects source
                     WHERE source.cache_id = ?1
                       AND source.id = cache_object_references.cache_object_id
                       AND source.lifecycle_state = 'tombstoned')",
                vals![cache_id, cache_object_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM cache_objects
                 WHERE cache_id = ?1 AND id = ?2 AND resource_version = ?3
                   AND lifecycle_state = 'tombstoned'
                   AND tombstoned_at + (SELECT tombstone_retention_secs
                     FROM cache_gc_policies WHERE cache_id = ?1) <= ?4
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     WHERE job.cache_id = ?1 AND job.active_slot = 1
                       AND (job.surface_object_id = narinfo_surface_object_id
                         OR job.surface_object_id = nar_surface_object_id))
                   AND NOT EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.cache_id = ?1
                       AND (presence.surface_object_id = narinfo_surface_object_id
                         OR presence.surface_object_id = nar_surface_object_id)
                       AND presence.state <> 'missing')
                   AND NOT EXISTS (SELECT 1 FROM cache_object_references edge
                     JOIN cache_objects live ON live.id = edge.cache_object_id
                       AND live.cache_id = edge.cache_id
                     WHERE edge.cache_id = ?1
                       AND edge.referenced_cache_object_id = ?2
                       AND live.lifecycle_state = 'active')",
                vals![
                    cache_id,
                    cache_object_id,
                    expected_object_version,
                    reaped_at
                ],
            )
            .expecting(1),
            Statement::new(
                "DELETE FROM object_placements WHERE cache_id = ?1
                   AND surface_object_id = ?2 AND state = 'missing'
                   AND NOT EXISTS (SELECT 1 FROM cache_objects
                     WHERE cache_id = ?1 AND narinfo_surface_object_id = ?2)",
                vals![cache_id, narinfo_surface_object_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM object_placements WHERE cache_id = ?1
                   AND surface_object_id = ?2 AND state = 'missing'
                   AND NOT EXISTS (SELECT 1 FROM cache_objects
                     WHERE cache_id = ?1 AND nar_surface_object_id = ?2)",
                vals![cache_id, nar_surface_object_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM cache_nar_objects
                 WHERE cache_id = ?1 AND nar_surface_object_id = ?2
                   AND NOT EXISTS (SELECT 1 FROM cache_objects
                     WHERE cache_id = ?1 AND nar_surface_object_id = ?2)",
                vals![cache_id, nar_surface_object_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM surface_objects WHERE cache_id = ?1 AND id = ?2
                   AND lifecycle_state = 'tombstoned'
                   AND NOT EXISTS (SELECT 1 FROM object_placements
                     WHERE cache_id = ?1 AND surface_object_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_actions
                     WHERE cache_id = ?1 AND surface_object_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs
                     WHERE cache_id = ?1 AND surface_object_id = ?2)",
                vals![cache_id, narinfo_surface_object_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM surface_objects WHERE cache_id = ?1 AND id = ?2
                   AND lifecycle_state = 'tombstoned'
                   AND NOT EXISTS (SELECT 1 FROM object_placements
                     WHERE cache_id = ?1 AND surface_object_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM cache_objects
                     WHERE cache_id = ?1 AND nar_surface_object_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_plan_actions
                     WHERE cache_id = ?1 AND surface_object_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs
                     WHERE cache_id = ?1 AND surface_object_id = ?2)",
                vals![cache_id, nar_surface_object_id],
            )
            .unchecked(),
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "object_graph_generation = object_graph_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "object_graph",
                reaped_at,
                &format!(
                    "NOT EXISTS (SELECT 1 FROM cache_objects WHERE cache_id = {} AND id = {})",
                    cache_id, cache_object_id
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Lists a bounded set of tombstones that are presently safe to reap.
    ///
    /// The mutation re-checks every predicate, so this query is only a bounded
    /// work selector rather than the authority for deletion.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit or database failure.
    pub async fn list_reapable_cache_object_tombstones(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<ReapableCacheObjectTombstone>> {
        if limit <= 0 {
            bail!("cache tombstone reap limit must be positive");
        }
        let rows = self
            .backend
            .query(
                "SELECT object.cache_id, object.id, object.resource_version
             FROM cache_objects object
             JOIN cache_gc_policies policy ON policy.cache_id = object.cache_id
             WHERE object.lifecycle_state = 'tombstoned'
               AND object.tombstoned_at + policy.tombstone_retention_secs <= ?1
               AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                 WHERE job.cache_id = object.cache_id AND job.active_slot = 1
                   AND (job.surface_object_id = object.narinfo_surface_object_id
                     OR job.surface_object_id = object.nar_surface_object_id))
               AND NOT EXISTS (SELECT 1 FROM object_placements presence
                 WHERE presence.cache_id = object.cache_id
                   AND (presence.surface_object_id = object.narinfo_surface_object_id
                     OR presence.surface_object_id = object.nar_surface_object_id)
                   AND presence.state <> 'missing')
               AND NOT EXISTS (SELECT 1 FROM cache_object_references edge
                 JOIN cache_objects live ON live.id = edge.cache_object_id
                   AND live.cache_id = edge.cache_id
                 WHERE edge.cache_id = object.cache_id
                   AND edge.referenced_cache_object_id = object.id
                   AND live.lifecycle_state = 'active')
             ORDER BY object.tombstoned_at, object.cache_id, object.id
             LIMIT ?2",
                &vals![now, limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ReapableCacheObjectTombstone {
                    cache_id: row.get(0)?,
                    cache_object_id: row.get(1)?,
                    resource_version: row.get(2)?,
                })
            })
            .collect()
    }

    /// Stages one immutable surface-object identity under a building inventory.
    ///
    /// This method never writes `surface_objects`; the identity is private to
    /// the generation until publication materializes it atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, a non-building generation,
    /// placement drift, a conflicting duplicate, or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_cache_surface_object_identity(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        object_key: &str,
        content_hash: &str,
        size: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        validate_key_bytes(object_key, "cache surface object key", 512)?;
        validate_key_bytes(content_hash, "cache surface object hash", 128)?;
        if cache_id <= 0 || generation <= 0 || placement_id <= 0 || size < 0 {
            bail!("cache staged surface-object identity is malformed");
        }
        let partition_key = sha2::Sha256::digest(object_key.as_bytes()).to_vec();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO cache_inventory_staged_surface_objects
                       (cache_id, generation, placement_id, object_key,
                        partition_key, content_hash, size)
                     SELECT ?1, ?2, placement.id, ?4, ?5, ?6, ?7
                     FROM surface_placements placement
                     JOIN cache_inventory_generations inventory
                       ON inventory.cache_id = ?1 AND inventory.generation = ?2
                     JOIN cache_inventory_placement_scans scan
                       ON scan.cache_id = inventory.cache_id
                      AND scan.generation = inventory.generation
                      AND scan.placement_id = placement.id
                     WHERE placement.id = ?3 AND placement.cache_id = ?1
                       AND inventory.state = 'building' AND inventory.owner_token = ?8
                       AND scan.completed_at IS NULL
                     ON CONFLICT(cache_id, generation, placement_id, object_key) DO NOTHING",
                    vals![
                        cache_id,
                        generation,
                        placement_id,
                        object_key,
                        partition_key,
                        content_hash,
                        size,
                        owner_token
                    ],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE cache_inventory_staged_surface_objects
                     SET object_key = object_key
                     WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
                       AND object_key = ?4 AND content_hash = ?5 AND size = ?6",
                    vals![
                        cache_id,
                        generation,
                        placement_id,
                        object_key,
                        content_hash,
                        size
                    ],
                )
                .expecting(1),
            ])
            .await
    }

    /// Reads one generation-scoped immutable surface-object identity.
    ///
    /// # Errors
    ///
    /// Returns an error for persistence failure or malformed persisted data.
    pub async fn cache_staged_surface_object_identity(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        object_key: &str,
    ) -> Result<Option<(String, i64)>> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        self.backend
            .query_opt(
                "SELECT staged.content_hash, staged.size
                 FROM cache_inventory_staged_surface_objects staged
                 JOIN cache_inventory_generations inventory
                   ON inventory.cache_id = staged.cache_id
                  AND inventory.generation = staged.generation
                 WHERE staged.cache_id = ?1 AND staged.generation = ?2
                   AND staged.placement_id = ?3 AND staged.object_key = ?4
                   AND inventory.state = 'building' AND inventory.owner_token = ?5",
                &vals![cache_id, generation, placement_id, object_key, owner_token],
            )
            .await?
            .map(|row| -> Result<_> { Ok((row.get(0)?, row.get(1)?)) })
            .transpose()
    }

    /// Stages one placement observation under a building cache-wide inventory.
    ///
    /// The active inventory pointer is not advanced here, so route and GC reads
    /// cannot mistake a partial scan for complete evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed state, missing/cross-cache resources, a
    /// non-building generation, or database failure.
    pub async fn stage_cache_object_presence(
        &self,
        owner_token: &str,
        input: &CacheObjectPresenceObservation,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if !matches!(
            input.state.as_str(),
            "present" | "copying" | "missing" | "corrupt" | "deleting"
        ) || input.cache_id <= 0
            || input.object_key.is_empty()
            || input.object_key.len() > 512
            || input.placement_id <= 0
            || input.inventory_generation <= 0
            || input.observed_size.is_some_and(|size| size < 0)
        {
            bail!("cache presence observation is malformed");
        }
        if input.state == "present"
            && (input.observed_hash.is_none() || input.observed_size.is_none())
        {
            bail!("present cache objects require an observed hash and size");
        }
        let statements = vec![
            Statement::new(
                "UPDATE cache_inventory_placement_scans
                 SET selected_at = selected_at
                 WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
                   AND completed_at IS NULL
                   AND EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                     WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                       AND inventory.state = 'building' AND inventory.owner_token = ?4)",
                vals![
                    input.cache_id,
                    input.inventory_generation,
                    input.placement_id,
                    owner_token
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_inventory_object_observations
                 (object_key, cache_id, generation, placement_id,
                  state, observed_hash, observed_size, etag, observed_at)
                 SELECT staged.object_key, ?3, ?4, placement.id, ?5, ?6, ?7, ?8, ?9
                 FROM cache_inventory_staged_surface_objects staged
                 JOIN surface_placements placement ON placement.id = ?2
                 JOIN cache_inventory_generations inventory
                   ON inventory.cache_id = ?3 AND inventory.generation = ?4
                 JOIN cache_inventory_placement_scans scan
                   ON scan.cache_id = inventory.cache_id
                  AND scan.generation = inventory.generation
                  AND scan.placement_id = placement.id
                 WHERE staged.object_key = ?1 AND staged.cache_id = ?3
                   AND staged.generation = ?4 AND staged.placement_id = ?2
                   AND placement.cache_id = ?3 AND inventory.state = 'building'
                   AND inventory.owner_token = ?10
                   AND scan.completed_at IS NULL
                   AND scan.placement_resource_version = placement.resource_version
                   AND (?5 <> 'present' OR (staged.content_hash = ?6
                     AND staged.size = ?7))",
                vals![
                    input.object_key,
                    input.placement_id,
                    input.cache_id,
                    input.inventory_generation,
                    input.state,
                    input.observed_hash,
                    input.observed_size,
                    input.etag,
                    input.observed_at,
                    owner_token
                ],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Begins the next cache-wide inventory generation under epoch CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-successor generation, stale epoch, or
    /// database failure.
    pub async fn begin_cache_inventory_topology(
        &self,
        cache_id: i64,
        generation: i64,
        expected_epoch: i64,
        owner_token: &str,
        created_at: i64,
        lease_expires_at: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if generation <= 1 || expected_epoch < 0 || lease_expires_at <= created_at {
            bail!("cache inventory successor generation or epoch is invalid");
        }
        let statements = vec![
            Statement::new(
                "DELETE FROM cache_inventory_generations
                 WHERE cache_id = ?1 AND generation = ?2
                   AND (state = 'failed'
                     OR (state = 'building' AND lease_expires_at <= ?3))",
                vals![cache_id, generation, created_at],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_inventory_generations
             (cache_id, generation, owner_token, lease_expires_at, state, created_at)
             SELECT state.cache_id, ?2, ?4, ?5, 'building', ?6
             FROM cache_gc_state state
             WHERE state.cache_id = ?1 AND state.epoch = ?3
               AND state.inventory_generation + 1 = ?2
               AND EXISTS (SELECT 1 FROM surface_placements placement
                 WHERE placement.cache_id = ?1
                   AND placement.desired_state <> 'offline')
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 WHERE ticket.cache_id = ?1 AND ticket.active_cache_slot = 1)",
                vals![
                    cache_id,
                    generation,
                    expected_epoch,
                    owner_token,
                    lease_expires_at,
                    created_at
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_inventory_placement_scans
                 (cache_id, generation, placement_id, placement_resource_version,
                  binding_id, binding_resource_version, selected_at)
                 SELECT ?1, ?2, placement.id, placement.resource_version,
                        binding.id, binding.resource_version, ?3
                 FROM surface_placements placement
                 JOIN bindings binding
                   ON binding.id = placement.binding_id
                 WHERE placement.cache_id = ?1
                   AND placement.desired_state <> 'offline'",
                vals![cache_id, generation, created_at],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Renews one live cache-inventory owner's staging lease.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership changed, the generation is no longer
    /// building, the new deadline is invalid or regresses, or persistence
    /// fails.
    pub async fn heartbeat_cache_inventory_topology(
        &self,
        cache_id: i64,
        generation: i64,
        owner_token: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if cache_id <= 0 || generation <= 0 || lease_expires_at <= now {
            bail!("cache inventory heartbeat is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_inventory_generations
                 SET lease_expires_at = ?5
                 WHERE cache_id = ?1 AND generation = ?2
                   AND owner_token = ?3 AND state = 'building'
                   AND lease_expires_at > ?4
                   AND ?5 >= lease_expires_at",
                vals![cache_id, generation, owner_token, now, lease_expires_at],
            )
            .expecting(1)])
            .await
    }

    /// Publishes one placement's complete scan manifest for a building inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, a missing placement or building
    /// inventory, duplicate manifest identity, or database failure.
    pub async fn stage_cache_inventory_manifest(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        content_digest: &str,
        object_count: i64,
        published_at: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if generation <= 0 || placement_id <= 0 || content_digest.is_empty() || object_count < 0 {
            bail!("cache inventory manifest identity is invalid");
        }
        let manifest_id = digest_text(&format!(
            "cache-inventory:{cache_id}:{generation}:{placement_id}:{content_digest}"
        ));
        let statements = vec![
            Statement::new(
                "INSERT INTO placement_delivery_manifests
             (manifest_id, placement_id, registry_id, cache_id, kind,
              cache_inventory_generation, content_digest, published_at)
             SELECT ?1, placement.id, NULL, ?2, 'cache_inventory', ?3, ?5, ?6
             FROM surface_placements placement
             JOIN bindings binding
               ON binding.id = placement.binding_id
             JOIN cache_inventory_generations inventory
               ON inventory.cache_id = placement.cache_id
              AND inventory.generation = ?3
             WHERE placement.id = ?4 AND placement.cache_id = ?2
               AND inventory.state = 'building' AND inventory.owner_token = ?7
               AND EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                 WHERE scan.cache_id = ?2 AND scan.generation = ?3
                   AND scan.placement_id = ?4 AND scan.completed_at IS NULL
                   AND scan.placement_resource_version = placement.resource_version
                   AND scan.binding_id = binding.id
                   AND scan.binding_resource_version = binding.resource_version)",
                vals![
                    manifest_id,
                    cache_id,
                    generation,
                    placement_id,
                    content_digest,
                    published_at,
                    owner_token
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_inventory_placement_scans
             SET content_digest = ?4, object_count = ?5, completed_at = ?6
             WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
               AND completed_at IS NULL
               AND EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                 WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                   AND inventory.state = 'building' AND inventory.owner_token = ?7)
               AND placement_resource_version = (SELECT resource_version
                 FROM surface_placements WHERE id = ?3 AND cache_id = ?1)
               AND binding_id = (SELECT binding_id
                 FROM surface_placements WHERE id = ?3 AND cache_id = ?1)
               AND binding_resource_version = (SELECT binding.resource_version
                 FROM surface_placements placement
                 JOIN bindings binding
                   ON binding.id = placement.binding_id
                 WHERE placement.id = ?3 AND placement.cache_id = ?1)",
                vals![
                    cache_id,
                    generation,
                    placement_id,
                    content_digest,
                    object_count,
                    published_at,
                    owner_token
                ],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Stages one listed key's byte identity under a building generation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence, a duplicate key, a missing
    /// placement scan, a non-building generation, or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_cache_inventory_listed_object(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        object_key: &str,
        observed_sha256: &str,
        observed_size: i64,
        etag: Option<&str>,
    ) -> Result<()> {
        self.stage_cache_inventory_listed_objects(
            cache_id,
            generation,
            placement_id,
            owner_token,
            &[CacheInventoryListedObject {
                object_key: object_key.to_string(),
                observed_sha256: observed_sha256.to_string(),
                observed_size,
                etag: etag.map(str::to_string),
            }],
        )
        .await
    }

    /// Stages one bounded page of listed byte identities atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized or malformed page, duplicate keys, a
    /// missing placement scan, a non-building generation, or persistence
    /// failure.
    pub async fn stage_cache_inventory_listed_objects(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        objects: &[CacheInventoryListedObject],
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if cache_id <= 0 || generation <= 0 || placement_id <= 0 {
            bail!("cache inventory listed-object evidence is invalid");
        }
        if objects.len() > MAX_CACHE_INVENTORY_LISTED_OBJECT_BATCH {
            bail!("cache inventory listed-object page exceeds its bound");
        }
        let mut keys = BTreeSet::new();
        for object in objects {
            if object.object_key.is_empty()
                || object.object_key.len() > 512
                || object.observed_sha256.len() != 64
                || !object
                    .observed_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || object.observed_size < 0
                || !keys.insert(object.object_key.as_str())
            {
                bail!("cache inventory listed-object evidence is invalid");
            }
        }

        let mut statements = Vec::with_capacity(objects.len() + 1);
        statements.push(CheckedStatement::exact(
            "UPDATE cache_inventory_placement_scans
                SET selected_at = selected_at
              WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
                AND completed_at IS NULL
                AND EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                    WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                      AND inventory.state = 'building' AND inventory.owner_token = ?4)",
            vals![cache_id, generation, placement_id, owner_token].to_vec(),
            1,
        ));
        statements.extend(objects.iter().map(|object| {
            CheckedStatement::unchecked(
                "INSERT INTO cache_inventory_listed_objects
                    (cache_id, generation, placement_id, object_key,
                     observed_sha256, observed_size, etag)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vals![
                    cache_id,
                    generation,
                    placement_id,
                    object.object_key.as_str(),
                    object.observed_sha256.as_str(),
                    object.observed_size,
                    object.etag.as_deref()
                ]
                .to_vec(),
            )
        }));
        self.backend.checked_batch(&statements).await
    }

    /// Reads previously staged listing evidence without loading an object body.
    ///
    /// # Errors
    ///
    /// Returns an error for database failure or malformed persisted evidence.
    pub async fn cache_inventory_listed_object_evidence(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        object_key: &str,
    ) -> Result<Option<(String, i64, Option<String>)>> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        let row = self
            .backend
            .query_opt(
                "SELECT listed.observed_sha256, listed.observed_size, listed.etag
                 FROM cache_inventory_listed_objects listed
                 JOIN cache_inventory_generations inventory
                   ON inventory.cache_id = listed.cache_id
                  AND inventory.generation = listed.generation
                 WHERE listed.cache_id = ?1 AND listed.generation = ?2
                   AND listed.placement_id = ?3 AND listed.object_key = ?4
                   AND inventory.state = 'building' AND inventory.owner_token = ?5",
                &vals![cache_id, generation, placement_id, object_key, owner_token],
            )
            .await?;
        row.map(|row| -> Result<_> { Ok((row.get(0)?, row.get(1)?, row.get(2)?)) })
            .transpose()
    }

    /// Stages one normalized narinfo identity in an unpublished inventory.
    ///
    /// The database index, rather than an in-memory pairwise walk, provides the
    /// conflict key used by publication to reject one immutable store hash with
    /// different normalized identities across placements.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, duplicate placement evidence,
    /// a non-building generation, or persistence failure.
    pub async fn stage_cache_inventory_narinfo_candidate(
        &self,
        owner_token: &str,
        input: &CacheInventoryNarinfoCandidate,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        validate_store_hash(&input.store_hash)?;
        if input.cache_id <= 0
            || input.generation <= 0
            || input.placement_id <= 0
            || input.identity_digest.len() != 64
            || input.narinfo_object_key.is_empty()
            || input.nar_object_key.is_empty()
            || input.narinfo_object_key == input.nar_object_key
            || input.store_name.is_empty()
            || input.nar_hash.is_empty()
            || input.nar_size < 0
            || input.file_hash.is_empty()
            || input.file_size < 0
            || input.compression.is_empty()
        {
            bail!("cache inventory narinfo candidate identity is invalid");
        }
        let mut references = input.references.clone();
        references.sort();
        references.dedup();
        if references != input.references {
            bail!("cache inventory candidate references must be sorted and deduplicated");
        }
        for reference in &references {
            validate_store_hash(reference)?;
        }
        let mut statements = vec![Statement::new(
            "INSERT INTO cache_inventory_narinfo_candidates
                 (cache_id, generation, store_hash, placement_id,
                  identity_digest, narinfo_object_key, nar_object_key,
                  store_name, nar_hash, nar_size, file_hash, file_size, compression,
                  deriver, signature, content_address, published_at)
             SELECT ?1, ?2, ?3, placement.id, ?5, narinfo.object_key, nar.object_key,
                    ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             FROM surface_placements placement
             JOIN cache_inventory_generations inventory
               ON inventory.cache_id = ?1 AND inventory.generation = ?2
             JOIN cache_inventory_placement_scans scan
               ON scan.cache_id = inventory.cache_id
              AND scan.generation = inventory.generation
              AND scan.placement_id = placement.id
             JOIN cache_inventory_staged_surface_objects narinfo
               ON narinfo.cache_id = ?1 AND narinfo.generation = ?2
              AND narinfo.placement_id = ?4 AND narinfo.object_key = ?6
             JOIN cache_inventory_staged_surface_objects nar
               ON nar.cache_id = ?1 AND nar.generation = ?2
              AND nar.placement_id = ?4 AND nar.object_key = ?7
             WHERE placement.id = ?4 AND placement.cache_id = ?1
               AND inventory.state = 'building' AND inventory.owner_token = ?18
               AND scan.completed_at IS NULL",
            vals![
                input.cache_id,
                input.generation,
                input.store_hash,
                input.placement_id,
                input.identity_digest,
                input.narinfo_object_key,
                input.nar_object_key,
                input.store_name,
                input.nar_hash,
                input.nar_size,
                input.file_hash,
                input.file_size,
                input.compression,
                input.deriver,
                input.signature,
                input.content_address,
                input.published_at,
                owner_token
            ],
        )
        .expecting(1)];
        for reference in references {
            statements.push(
                Statement::new(
                    "INSERT INTO cache_inventory_candidate_references
                         (cache_id, generation, store_hash, placement_id,
                          referenced_store_hash)
                     SELECT cache_id, generation, store_hash, placement_id, ?5
                     FROM cache_inventory_narinfo_candidates
                     WHERE cache_id = ?1 AND generation = ?2
                       AND store_hash = ?3 AND placement_id = ?4",
                    vals![
                        input.cache_id,
                        input.generation,
                        input.store_hash,
                        input.placement_id,
                        reference
                    ],
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await
    }

    /// Stages `missing` observations for catalogued objects not listed by one scan.
    ///
    /// Existing observations always win. The rows remain generation-scoped and
    /// invisible to readers until [`Self::publish_cache_inventory_topology`]
    /// atomically replaces the published placement state. The generation-wide
    /// immutable-key union is copied into this placement first, so a new object
    /// discovered on another replica or shard gets explicit `missing` evidence
    /// without becoming globally visible before publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement scan is absent or complete, the
    /// generation is not building, or persistence fails.
    pub async fn stage_missing_cache_inventory_observations(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
        observed_at: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        if cache_id <= 0 || generation <= 0 || placement_id <= 0 {
            bail!("cache inventory missing-observation identity is invalid");
        }
        let statements = vec![
            Statement::new(
                "UPDATE cache_inventory_placement_scans
                 SET selected_at = selected_at
                 WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
                   AND completed_at IS NULL
                   AND EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                     WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                       AND inventory.state = 'building' AND inventory.owner_token = ?4)",
                vals![cache_id, generation, placement_id, owner_token],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_inventory_staged_surface_objects
                   (cache_id, generation, placement_id, object_key,
                    partition_key, content_hash, size)
                 SELECT canonical.cache_id, canonical.generation, ?3,
                        canonical.object_key, canonical.partition_key,
                        canonical.content_hash, canonical.size
                 FROM cache_inventory_staged_surface_objects canonical
                 JOIN cache_inventory_generations inventory
                   ON inventory.cache_id = canonical.cache_id
                  AND inventory.generation = canonical.generation
                 WHERE canonical.cache_id = ?1 AND canonical.generation = ?2
                   AND inventory.state = 'building' AND inventory.owner_token = ?4
                   AND canonical.placement_id = (SELECT MIN(source.placement_id)
                     FROM cache_inventory_staged_surface_objects source
                     WHERE source.cache_id = canonical.cache_id
                       AND source.generation = canonical.generation
                       AND source.object_key = canonical.object_key)
                   AND NOT EXISTS (SELECT 1
                     FROM cache_inventory_staged_surface_objects conflict
                     WHERE conflict.cache_id = canonical.cache_id
                       AND conflict.generation = canonical.generation
                       AND conflict.object_key = canonical.object_key
                       AND (conflict.partition_key <> canonical.partition_key
                         OR conflict.content_hash <> canonical.content_hash
                         OR conflict.size <> canonical.size))
                 ON CONFLICT(cache_id, generation, placement_id, object_key) DO NOTHING",
                vals![cache_id, generation, placement_id, owner_token],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_inventory_staged_surface_objects
                   (cache_id, generation, placement_id, object_key,
                    partition_key, content_hash, size)
                 SELECT object.cache_id, ?2, ?3, object.object_key,
                        object.partition_key, object.content_hash, object.size
                 FROM surface_objects object
                 JOIN cache_inventory_generations inventory
                   ON inventory.cache_id = ?1 AND inventory.generation = ?2
                 JOIN cache_inventory_placement_scans scan
                   ON scan.cache_id = inventory.cache_id
                  AND scan.generation = inventory.generation
                  AND scan.placement_id = ?3
                 WHERE object.cache_id = ?1 AND object.object_kind = 'immutable'
                   AND object.content_hash IS NOT NULL AND object.size IS NOT NULL
                   AND inventory.state = 'building' AND inventory.owner_token = ?4
                   AND scan.completed_at IS NULL
                 ON CONFLICT(cache_id, generation, placement_id, object_key) DO NOTHING",
                vals![cache_id, generation, placement_id, owner_token],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_inventory_object_observations
                 (object_key, cache_id, generation, placement_id,
                  state, observed_hash, observed_size, etag, observed_at)
             SELECT staged.object_key, ?1, ?2, ?3, 'missing', NULL, NULL, NULL, ?4
             FROM cache_inventory_staged_surface_objects staged
             JOIN cache_inventory_generations inventory
               ON inventory.cache_id = ?1 AND inventory.generation = ?2
             JOIN cache_inventory_placement_scans scan
               ON scan.cache_id = inventory.cache_id
              AND scan.generation = inventory.generation
              AND scan.placement_id = ?3
             WHERE staged.cache_id = ?1 AND staged.generation = ?2
               AND staged.placement_id = ?3 AND inventory.state = 'building'
               AND inventory.owner_token = ?5
               AND scan.completed_at IS NULL
               AND NOT EXISTS (SELECT 1
                 FROM cache_inventory_object_observations observation
                 WHERE observation.cache_id = ?1
                   AND observation.generation = ?2
                   AND observation.placement_id = ?3
                   AND observation.object_key = staged.object_key)",
                vals![cache_id, generation, placement_id, observed_at, owner_token],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Discards normalized candidates whose source placement lacks exact bytes.
    ///
    /// The physical inventory still publishes missing/corrupt observations;
    /// only the derived browse graph candidate is removed.
    ///
    /// # Errors
    ///
    /// Returns an error for database failure.
    pub async fn discard_unservable_cache_inventory_candidates(
        &self,
        cache_id: i64,
        generation: i64,
        placement_id: i64,
        owner_token: &str,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        self.backend
            .checked_batch(&[Statement::new(
                "DELETE FROM cache_inventory_narinfo_candidates
                 WHERE cache_id = ?1 AND generation = ?2 AND placement_id = ?3
                   AND EXISTS (SELECT 1 FROM cache_inventory_generations inventory
                     WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                       AND inventory.state = 'building' AND inventory.owner_token = ?4)
                   AND (NOT EXISTS (SELECT 1
                     FROM cache_inventory_object_observations observation
                     WHERE observation.cache_id = ?1
                       AND observation.generation = ?2
                       AND observation.placement_id = ?3
                       AND observation.object_key = narinfo_object_key
                       AND observation.state = 'present')
                     OR NOT EXISTS (SELECT 1
                       FROM cache_inventory_object_observations observation
                       WHERE observation.cache_id = ?1
                         AND observation.generation = ?2
                         AND observation.placement_id = ?3
                         AND observation.object_key = nar_object_key
                         AND observation.state = 'present'))",
                vals![cache_id, generation, placement_id, owner_token],
            )
            .unchecked()])
            .await
    }

    /// Returns candidate-vs-active graph counts without materializing either set.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing building generation, database failure, or
    /// malformed aggregate values.
    pub async fn cache_inventory_change_counts(
        &self,
        cache_id: i64,
        generation: i64,
        owner_token: &str,
    ) -> Result<(i64, i64, i64)> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        let rows = self
            .backend
            .query(
                "SELECT
                   (SELECT COUNT(*) FROM (
                      SELECT candidate.store_hash
                      FROM cache_inventory_narinfo_candidates candidate
                      WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                      GROUP BY candidate.store_hash) candidates
                    WHERE NOT EXISTS (SELECT 1 FROM cache_objects object
                      WHERE object.cache_id = ?1
                        AND object.store_hash = candidates.store_hash
                        AND object.lifecycle_state = 'active')),
                   (SELECT COUNT(*) FROM cache_objects object
                    WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                      AND NOT EXISTS (SELECT 1
                        FROM cache_inventory_narinfo_candidates candidate
                        WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                          AND candidate.store_hash = object.store_hash)),
                   (SELECT COUNT(*) FROM cache_objects object
                    WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                      AND EXISTS (SELECT 1
                        FROM cache_inventory_narinfo_candidates candidate
                        WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                          AND candidate.store_hash = object.store_hash))
                 FROM cache_inventory_generations inventory
                 WHERE inventory.cache_id = ?1 AND inventory.generation = ?2
                   AND inventory.state = 'building' AND inventory.owner_token = ?3",
                &vals![cache_id, generation, owner_token],
            )
            .await?;
        let row = rows
            .first()
            .context("cache inventory generation is not building")?;
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }

    /// Publishes one complete cache-wide inventory and advances the GC epoch.
    ///
    /// Every placement selected when the generation began must complete its
    /// own manifest. Placement manifests may differ for sharded caches; the
    /// supplied digest identifies the deterministic cache-wide aggregate.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete placement coverage, a stale epoch,
    /// terminal generation, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_cache_inventory_topology(
        &self,
        cache_id: i64,
        generation: i64,
        owner_token: &str,
        content_digest: &str,
        expected_epoch: i64,
        mutation_id: &str,
        published_at: i64,
    ) -> Result<()> {
        validate_stable_key(owner_token, "cache inventory owner token")?;
        validate_stable_key(mutation_id, "cache inventory mutation id")?;
        if generation <= 0 || expected_epoch < 0 || content_digest.is_empty() {
            bail!("cache inventory generation, epoch, or digest is invalid");
        }
        let statements = vec![
            Statement::new(
                "UPDATE cache_inventory_generations
                 SET state = 'published', content_digest = ?3, published_at = ?4
                 WHERE cache_id = ?1 AND generation = ?2 AND state = 'building'
                   AND owner_token = ?5
                   AND lease_expires_at > ?4
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     WHERE job.cache_id = ?1 AND job.active_slot = 1)
                   AND EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                     WHERE scan.cache_id = ?1 AND scan.generation = ?2)
                   AND NOT EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                     WHERE scan.cache_id = ?1 AND scan.generation = ?2
                       AND scan.completed_at IS NULL)
                   AND NOT EXISTS (
                     SELECT 1
                     FROM cache_inventory_narinfo_candidates candidate
                     JOIN cache_inventory_narinfo_candidates other
                       ON other.cache_id = candidate.cache_id
                      AND other.generation = candidate.generation
                      AND other.store_hash = candidate.store_hash
                     AND other.identity_digest <> candidate.identity_digest
                     WHERE candidate.cache_id = ?1 AND candidate.generation = ?2)
                   AND NOT EXISTS (
                     SELECT 1
                     FROM cache_inventory_staged_surface_objects staged
                     JOIN cache_inventory_staged_surface_objects other
                       ON other.cache_id = staged.cache_id
                      AND other.generation = staged.generation
                      AND other.object_key = staged.object_key
                      AND other.placement_id <> staged.placement_id
                     WHERE staged.cache_id = ?1 AND staged.generation = ?2
                       AND (other.content_hash <> staged.content_hash
                         OR other.size <> staged.size
                         OR other.partition_key <> staged.partition_key))
                   AND NOT EXISTS (
                     SELECT 1
                     FROM cache_inventory_staged_surface_objects staged
                     JOIN surface_objects object
                       ON object.cache_id = staged.cache_id
                      AND object.object_key = staged.object_key
                     WHERE staged.cache_id = ?1 AND staged.generation = ?2
                       AND (object.object_kind <> 'immutable'
                         OR object.content_hash <> staged.content_hash
                         OR object.size <> staged.size
                         OR object.partition_key <> staged.partition_key))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_inventory_narinfo_candidates candidate
                     WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                       AND (NOT EXISTS (SELECT 1
                         FROM cache_inventory_object_observations observation
                         WHERE observation.cache_id = candidate.cache_id
                           AND observation.generation = candidate.generation
                           AND observation.placement_id = candidate.placement_id
                           AND observation.object_key = candidate.narinfo_object_key
                           AND observation.state = 'present')
                         OR NOT EXISTS (SELECT 1
                           FROM cache_inventory_object_observations observation
                           WHERE observation.cache_id = candidate.cache_id
                             AND observation.generation = candidate.generation
                             AND observation.placement_id = candidate.placement_id
                             AND observation.object_key = candidate.nar_object_key
                             AND observation.state = 'present')))
                   AND NOT EXISTS (
                     SELECT 1
                     FROM cache_inventory_narinfo_candidates candidate
                     JOIN cache_objects object
                       ON object.cache_id = candidate.cache_id
                      AND object.store_hash = candidate.store_hash
                     WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                       AND candidate.placement_id = (SELECT MIN(canonical.placement_id)
                         FROM cache_inventory_narinfo_candidates canonical
                         WHERE canonical.cache_id = candidate.cache_id
                           AND canonical.generation = candidate.generation
                           AND canonical.store_hash = candidate.store_hash)
                       AND (object.store_name <> candidate.store_name
                         OR NOT EXISTS (SELECT 1 FROM surface_objects narinfo
                           WHERE narinfo.id = object.narinfo_surface_object_id
                             AND narinfo.cache_id = object.cache_id
                             AND narinfo.object_key = candidate.narinfo_object_key)
                         OR NOT EXISTS (SELECT 1 FROM surface_objects nar
                           WHERE nar.id = object.nar_surface_object_id
                             AND nar.cache_id = object.cache_id
                             AND nar.object_key = candidate.nar_object_key)
                         OR object.nar_hash <> candidate.nar_hash
                         OR object.nar_size <> candidate.nar_size
                         OR object.file_hash <> candidate.file_hash
                         OR object.file_size <> candidate.file_size
                         OR object.compression <> candidate.compression
                         OR COALESCE(object.deriver, '') <> COALESCE(candidate.deriver, '')
                         OR COALESCE(object.signature, '') <> COALESCE(candidate.signature, '')
                         OR COALESCE(object.content_address, '') <> COALESCE(candidate.content_address, '')
                         OR object.reference_count <> (SELECT COUNT(*)
                           FROM cache_inventory_candidate_references reference
                           WHERE reference.cache_id = candidate.cache_id
                             AND reference.generation = candidate.generation
                             AND reference.store_hash = candidate.store_hash
                             AND reference.placement_id = candidate.placement_id)
                         OR EXISTS (SELECT 1 FROM cache_object_references edge
                           WHERE edge.cache_id = object.cache_id
                             AND edge.cache_object_id = object.id
                             AND NOT EXISTS (SELECT 1
                               FROM cache_inventory_candidate_references reference
                               WHERE reference.cache_id = candidate.cache_id
                                 AND reference.generation = candidate.generation
                                 AND reference.store_hash = candidate.store_hash
                                 AND reference.placement_id = candidate.placement_id
                                 AND reference.referenced_store_hash = edge.referenced_store_hash))
                         OR EXISTS (SELECT 1
                           FROM cache_inventory_candidate_references reference
                           WHERE reference.cache_id = candidate.cache_id
                             AND reference.generation = candidate.generation
                             AND reference.store_hash = candidate.store_hash
                             AND reference.placement_id = candidate.placement_id
                             AND NOT EXISTS (SELECT 1 FROM cache_object_references edge
                               WHERE edge.cache_id = object.cache_id
                                 AND edge.cache_object_id = object.id
                                 AND edge.referenced_store_hash = reference.referenced_store_hash))))
                   AND NOT EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                     LEFT JOIN surface_placements placement
                       ON placement.id = scan.placement_id
                      AND placement.cache_id = scan.cache_id
                     LEFT JOIN bindings binding
                       ON binding.id = placement.binding_id
                     WHERE scan.cache_id = ?1 AND scan.generation = ?2
                       AND (placement.id IS NULL OR placement.desired_state = 'offline'
                         OR placement.resource_version <> scan.placement_resource_version
                         OR placement.binding_id <> scan.binding_id
                         OR binding.resource_version <> scan.binding_resource_version))
                   AND NOT EXISTS (SELECT 1 FROM surface_placements placement
                     WHERE placement.cache_id = ?1
                       AND placement.desired_state <> 'offline'
                       AND NOT EXISTS (SELECT 1
                         FROM cache_inventory_placement_scans scan
                         WHERE scan.cache_id = ?1 AND scan.generation = ?2
                           AND scan.placement_id = placement.id))",
                vals![cache_id, generation, content_digest, published_at, owner_token],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO surface_objects
                   (cache_id, object_key, object_kind, partition_key,
                    content_hash, size, lifecycle_state, created_at, updated_at)
                 SELECT staged.cache_id, staged.object_key, 'immutable',
                        staged.partition_key, staged.content_hash, staged.size,
                        'active', ?3, ?3
                 FROM cache_inventory_staged_surface_objects staged
                 WHERE staged.cache_id = ?1 AND staged.generation = ?2
                   AND staged.placement_id = (SELECT MIN(canonical.placement_id)
                     FROM cache_inventory_staged_surface_objects canonical
                     WHERE canonical.cache_id = staged.cache_id
                       AND canonical.generation = staged.generation
                       AND canonical.object_key = staged.object_key)
                   AND NOT EXISTS (SELECT 1 FROM surface_objects object
                     WHERE object.cache_id = staged.cache_id
                       AND object.object_key = staged.object_key)",
                vals![cache_id, generation, published_at],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_nar_objects
                   (cache_id, nar_surface_object_id, nar_hash, nar_size,
                    file_hash, file_size, compression, resource_version)
                 SELECT candidate.cache_id, nar.id,
                        candidate.nar_hash, candidate.nar_size,
                        candidate.file_hash, candidate.file_size,
                        candidate.compression, 1
                 FROM cache_inventory_narinfo_candidates candidate
                 JOIN surface_objects nar
                   ON nar.cache_id = candidate.cache_id
                  AND nar.object_key = candidate.nar_object_key
                 WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                   AND candidate.placement_id = (SELECT MIN(canonical.placement_id)
                     FROM cache_inventory_narinfo_candidates canonical
                     WHERE canonical.cache_id = candidate.cache_id
                       AND canonical.generation = candidate.generation
                       AND canonical.store_hash = candidate.store_hash)
                 ON CONFLICT(cache_id, nar_surface_object_id) DO NOTHING",
                vals![cache_id, generation],
            )
            .unchecked(),
            Statement::new(
                "UPDATE surface_objects
                 SET lifecycle_state = 'active', tombstoned_at = NULL,
                     updated_at = ?3, resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND lifecycle_state = 'tombstoned'
                   AND object_key IN (
                     SELECT narinfo_object_key
                     FROM cache_inventory_narinfo_candidates
                     WHERE cache_id = ?1 AND generation = ?2
                     UNION
                     SELECT nar_object_key
                     FROM cache_inventory_narinfo_candidates
                     WHERE cache_id = ?1 AND generation = ?2)",
                vals![cache_id, generation, published_at],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_objects
                 SET lifecycle_state = 'active', tombstoned_at = NULL,
                     unreferenced_since = NULL,
                     published_at = ?3,
                     resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND lifecycle_state = 'tombstoned'
                   AND EXISTS (SELECT 1
                     FROM cache_inventory_narinfo_candidates candidate
                     WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                       AND candidate.store_hash = cache_objects.store_hash
                       AND candidate.placement_id = (SELECT MIN(canonical.placement_id)
                         FROM cache_inventory_narinfo_candidates canonical
                         WHERE canonical.cache_id = candidate.cache_id
                           AND canonical.generation = candidate.generation
                           AND canonical.store_hash = candidate.store_hash))",
                vals![cache_id, generation, published_at],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_objects
                   (id, cache_id, store_hash, store_name,
                    narinfo_surface_object_id, nar_surface_object_id,
                    nar_hash, nar_size, file_hash, file_size, compression,
                    deriver, signature, content_address, reference_count,
                    lifecycle_state, published_at, resource_version)
                 SELECT narinfo.id, candidate.cache_id,
                        candidate.store_hash, candidate.store_name,
                        narinfo.id, nar.id,
                        candidate.nar_hash, candidate.nar_size,
                        candidate.file_hash, candidate.file_size, candidate.compression,
                        candidate.deriver, candidate.signature, candidate.content_address,
                        (SELECT COUNT(*) FROM cache_inventory_candidate_references reference
                         WHERE reference.cache_id = candidate.cache_id
                           AND reference.generation = candidate.generation
                           AND reference.store_hash = candidate.store_hash
                           AND reference.placement_id = candidate.placement_id),
                        'active', candidate.published_at, 1
                 FROM cache_inventory_narinfo_candidates candidate
                 JOIN surface_objects narinfo
                   ON narinfo.cache_id = candidate.cache_id
                  AND narinfo.object_key = candidate.narinfo_object_key
                 JOIN surface_objects nar
                   ON nar.cache_id = candidate.cache_id
                  AND nar.object_key = candidate.nar_object_key
                 WHERE candidate.cache_id = ?1 AND candidate.generation = ?2
                   AND candidate.placement_id = (SELECT MIN(canonical.placement_id)
                     FROM cache_inventory_narinfo_candidates canonical
                     WHERE canonical.cache_id = candidate.cache_id
                       AND canonical.generation = candidate.generation
                       AND canonical.store_hash = candidate.store_hash)
                   AND NOT EXISTS (SELECT 1 FROM cache_objects object
                     WHERE object.cache_id = candidate.cache_id
                       AND object.store_hash = candidate.store_hash)",
                vals![cache_id, generation],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO cache_object_references
                   (cache_id, cache_object_id, referenced_store_hash,
                    referenced_cache_object_id)
                 SELECT reference.cache_id, object.id,
                        reference.referenced_store_hash, target.id
                 FROM cache_inventory_candidate_references reference
                 JOIN cache_inventory_narinfo_candidates candidate
                   ON candidate.cache_id = reference.cache_id
                  AND candidate.generation = reference.generation
                  AND candidate.store_hash = reference.store_hash
                  AND candidate.placement_id = reference.placement_id
                 JOIN cache_objects object
                   ON object.cache_id = reference.cache_id
                  AND object.store_hash = reference.store_hash
                 LEFT JOIN cache_objects target
                   ON target.cache_id = reference.cache_id
                  AND target.store_hash = reference.referenced_store_hash
                  AND target.lifecycle_state = 'active'
                 WHERE reference.cache_id = ?1 AND reference.generation = ?2
                   AND reference.placement_id = (SELECT MIN(canonical.placement_id)
                     FROM cache_inventory_narinfo_candidates canonical
                     WHERE canonical.cache_id = reference.cache_id
                       AND canonical.generation = reference.generation
                       AND canonical.store_hash = reference.store_hash)
                 ON CONFLICT(cache_id, cache_object_id, referenced_store_hash) DO NOTHING",
                vals![cache_id, generation],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_object_references
                 SET referenced_cache_object_id = (SELECT target.id
                   FROM cache_objects target
                   WHERE target.cache_id = cache_object_references.cache_id
                     AND target.store_hash = cache_object_references.referenced_store_hash
                     AND target.lifecycle_state = 'active')
                 WHERE cache_id = ?1 AND referenced_cache_object_id IS NULL
                   AND EXISTS (SELECT 1 FROM cache_objects target
                     WHERE target.cache_id = cache_object_references.cache_id
                       AND target.store_hash = cache_object_references.referenced_store_hash
                       AND target.lifecycle_state = 'active')",
                vals![cache_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM object_placements
                 WHERE cache_id = ?1
                   AND placement_id IN (SELECT placement_id
                     FROM cache_inventory_placement_scans
                     WHERE cache_id = ?1 AND generation = ?2)",
                vals![cache_id, generation],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO object_placements
                 (surface_object_id, cache_id, registry_id, placement_id,
                  state, observed_hash, observed_size, etag,
                  observed_inventory_generation, observed_at,
                  catalog_object_resource_version)
                 SELECT object.id, observation.cache_id,
                        NULL, observation.placement_id, observation.state,
                        observation.observed_hash, observation.observed_size,
                        observation.etag, observation.generation,
                        observation.observed_at, object.resource_version
                 FROM cache_inventory_object_observations observation
                 JOIN surface_objects object
                   ON object.cache_id = observation.cache_id
                  AND object.object_key = observation.object_key
                 WHERE observation.cache_id = ?1
                   AND observation.generation = ?2",
                vals![cache_id, generation],
            )
            .unchecked(),
            Statement::new(
                "UPDATE cache_write_tickets
                 SET covered_inventory_generation = ?2,
                     resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND state = 'completed'
                   AND covered_inventory_generation IS NULL
                   AND finished_at <= (SELECT created_at
                     FROM cache_inventory_generations
                     WHERE cache_id = ?1 AND generation = ?2
                       AND state = 'published')",
                vals![cache_id, generation],
            )
            .unchecked(),
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                &format!(
                    "inventory_generation = {generation}, object_graph_generation = object_graph_generation + 1"
                ),
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "inventory",
                published_at,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_inventory_generations WHERE cache_id = {} AND generation = {} AND state = 'published')",
                    cache_id, generation
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Applies one immutable reviewed GC manifest exactly once.
    ///
    /// Apply claims the expected epoch, logically tombstones every candidate,
    /// creates or reuses exact placement-scoped deletion jobs, and links one
    /// operation in a single checked atomic batch. On crash or retry, the
    /// persisted plan-to-operation relation is returned only when the actor and
    /// confirmation inputs still match.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan expired, was already used with different
    /// inputs, has coverage failures, any root/graph/inventory/policy/topology/
    /// presence/fence predicate changed, or persistence fails.
    pub async fn apply_cache_gc_plan_topology(&self, input: &ApplyCacheGcPlan) -> Result<String> {
        validate_stable_key(&input.plan_id, "cache GC plan id")?;
        validate_stable_key(&input.claim_id, "cache GC claim id")?;
        validate_stable_key(&input.operation_id, "cache GC operation id")?;
        if input.actor_scope_digest.is_empty() || input.confirmation_hash.is_empty() {
            bail!("cache GC apply requires actor-scope and confirmation digests");
        }

        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT operation_id FROM cache_gc_plans
                 WHERE plan_id = ?1 AND applied_at IS NOT NULL
                   AND actor_scope_digest = ?2 AND confirmation_hash = ?3",
                &vals![
                    input.plan_id,
                    input.actor_scope_digest,
                    input.confirmation_hash
                ],
            )
            .await?
        {
            let existing: String = row.get(0)?;
            if existing != input.operation_id {
                bail!("cache GC plan was applied to a different operation identity");
            }
            return Ok(existing);
        }

        let plan = self
            .backend
            .query_opt(
                "SELECT cache_id, expected_epoch,
                   (SELECT COUNT(*) FROM cache_gc_plan_objects object
                     WHERE object.cache_id = plan.cache_id
                       AND object.plan_id = plan.plan_id),
                   (SELECT COUNT(*) FROM cache_gc_plan_actions action
                     WHERE action.cache_id = plan.cache_id
                       AND action.plan_id = plan.plan_id),
                   (SELECT retry_max_attempts FROM cache_gc_policies policy
                     WHERE policy.cache_id = plan.cache_id),
                   generation_id, input_versions_digest, manifest_digest,
                   actor_scope_digest, confirmation_hash, created_by,
                   request_idempotency_key, request_digest, created_at, expires_at
                 FROM cache_gc_plans plan WHERE plan_id = ?1",
                &vals![input.plan_id],
            )
            .await?
            .context("cache GC plan does not exist")?;
        let cache_id: i64 = plan.get(0)?;
        let expected_epoch: i64 = plan.get(1)?;
        let object_count: i64 = plan.get(2)?;
        let action_count: i64 = plan.get(3)?;
        let max_attempts: i64 = plan.get(4)?;
        let generation_id: String = plan.get(5)?;
        let persisted_input_versions_digest: String = plan.get(6)?;
        let persisted_manifest_digest: String = plan.get(7)?;
        let persisted_actor_scope_digest: String = plan.get(8)?;
        let persisted_confirmation_hash: String = plan.get(9)?;
        let persisted_created_by: String = plan.get(10)?;
        let persisted_request_idempotency_key: String = plan.get(11)?;
        let persisted_request_digest: String = plan.get(12)?;
        let persisted_created_at: i64 = plan.get(13)?;
        let persisted_expires_at: i64 = plan.get(14)?;
        let operation_state = if action_count == 0 {
            "succeeded"
        } else {
            "pending"
        };
        let operation_terminal_at = (action_count == 0).then_some(input.now);
        let expected_object_rows =
            u64::try_from(object_count).context("cache GC object count is negative")?;
        let actions = self
            .backend
            .query(
                "SELECT action_id, surface_object_id, placement_id, phase,
                   expected_etag, expected_hash, expected_size,
                   expected_inventory_generation,
                   binding_id, binding_resource_version,
                   delete_credential_generation,
                   estimated_reclaimable_bytes,
                   (SELECT COUNT(*) FROM cache_gc_action_dependencies dependency
                     WHERE dependency.cache_id = action.cache_id
                       AND dependency.plan_id = action.plan_id
                       AND dependency.action_id = action.action_id)
                 FROM cache_gc_plan_actions action
                 WHERE cache_id = ?1 AND plan_id = ?2
                 ORDER BY action_id",
                &vals![cache_id, input.plan_id],
            )
            .await?;
        if i64::try_from(actions.len()).ok() != Some(action_count) {
            bail!("cache GC action manifest changed while loading apply inputs");
        }
        let object_rows = self
            .backend
            .query(
                "SELECT cache_object_id, store_hash, expected_object_version,
                   expected_unreferenced_since, eligibility_reason, logical_bytes
                 FROM cache_gc_plan_objects
                 WHERE cache_id = ?1 AND plan_id = ?2
                 ORDER BY cache_object_id",
                &vals![cache_id, input.plan_id],
            )
            .await?;
        let object_action_rows = self
            .backend
            .query(
                "SELECT cache_object_id, action_id
                 FROM cache_gc_plan_object_actions
                 WHERE cache_id = ?1 AND plan_id = ?2
                 ORDER BY cache_object_id, action_id",
                &vals![cache_id, input.plan_id],
            )
            .await?;
        let dependency_rows = self
            .backend
            .query(
                "SELECT action_id, prerequisite_action_id
                 FROM cache_gc_action_dependencies
                 WHERE cache_id = ?1 AND plan_id = ?2
                 ORDER BY action_id, prerequisite_action_id",
                &vals![cache_id, input.plan_id],
            )
            .await?;
        let persisted_manifest = CreateCacheGcPlan {
            plan_id: input.plan_id.clone(),
            cache_id,
            generation_id: generation_id.clone(),
            expected_epoch,
            input_versions_digest: persisted_input_versions_digest.clone(),
            manifest_digest: persisted_manifest_digest.clone(),
            actor_scope_digest: persisted_actor_scope_digest.clone(),
            confirmation_hash: persisted_confirmation_hash.clone(),
            created_by: persisted_created_by,
            request_idempotency_key: persisted_request_idempotency_key,
            request_digest: persisted_request_digest,
            created_at: persisted_created_at,
            expires_at: persisted_expires_at,
            objects: object_rows
                .iter()
                .map(|row| {
                    Ok(CacheGcPlanObjectInput {
                        cache_object_id: row.get(0)?,
                        store_hash: row.get(1)?,
                        expected_object_version: row.get(2)?,
                        expected_unreferenced_since: row.get(3)?,
                        eligibility_reason: row.get(4)?,
                        logical_bytes: row.get(5)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            actions: actions
                .iter()
                .map(|row| {
                    Ok(CacheGcPlanActionInput {
                        action_id: row.get(0)?,
                        surface_object_id: row.get(1)?,
                        placement_id: row.get(2)?,
                        phase: row.get(3)?,
                        expected_etag: row.get(4)?,
                        expected_hash: row.get(5)?,
                        expected_size: row.get(6)?,
                        expected_inventory_generation: row.get(7)?,
                        binding_id: row.get(8)?,
                        binding_resource_version: row.get(9)?,
                        delete_credential_generation: row.get(10)?,
                        estimated_reclaimable_bytes: row.get(11)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            object_actions: object_action_rows
                .iter()
                .map(|row| {
                    Ok(CacheGcPlanObjectActionInput {
                        cache_object_id: row.get(0)?,
                        action_id: row.get(1)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            dependencies: dependency_rows
                .iter()
                .map(|row| {
                    Ok(CacheGcActionDependencyInput {
                        action_id: row.get(0)?,
                        prerequisite_action_id: row.get(1)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let generation = self
            .backend
            .query_opt(
                "SELECT expected_epoch, root_generation,
                   object_graph_generation, inventory_generation,
                   gc_policy_version, topology_version, root_count,
                   marked_object_count, coverage_error_count,
                   parent_mark_generation_id
                 FROM cache_gc_generations
                 WHERE cache_id = ?1 AND generation_id = ?2
                   AND state = 'complete'",
                &vals![cache_id, generation_id],
            )
            .await?
            .context("cache GC plan lost its complete mark generation")?;
        let topology_snapshot_digest = self
            .cache_gc_generation_topology_digest(cache_id, &generation_id)
            .await?;
        let derived_input_versions_digest = digest_text(&format!(
            "cache={};epoch={};roots={};graph={};inventory={};policy={};topology={};topology_snapshot={};root_count={};mark_count={};coverage_errors={};parent_mark={:?}",
            cache_id,
            generation.get::<i64>(0)?,
            generation.get::<i64>(1)?,
            generation.get::<i64>(2)?,
            generation.get::<i64>(3)?,
            generation.get::<i64>(4)?,
            generation.get::<i64>(5)?,
            topology_snapshot_digest,
            generation.get::<i64>(6)?,
            generation.get::<i64>(7)?,
            generation.get::<i64>(8)?,
            generation.get::<Option<String>>(9)?,
        ));
        let derived_manifest_digest = cache_gc_manifest_digest(&persisted_manifest)?;
        let derived_confirmation_hash = digest_text(&format!(
            "plan={};inputs={};manifest={};actor_scope={};expires_at={}",
            input.plan_id,
            derived_input_versions_digest,
            derived_manifest_digest,
            persisted_actor_scope_digest,
            persisted_expires_at
        ));
        if derived_input_versions_digest != persisted_input_versions_digest
            || derived_manifest_digest != persisted_manifest_digest
            || derived_confirmation_hash != persisted_confirmation_hash
            || persisted_actor_scope_digest != input.actor_scope_digest
            || persisted_confirmation_hash != input.confirmation_hash
        {
            bail!("persisted cache GC plan digests do not match their relational manifest");
        }

        let mut statements = vec![
            Statement::new(
                "INSERT INTO cache_gc_apply_claims
                 (cache_id, plan_id, claim_id, expected_epoch,
                  manifest_digest, actor_scope_digest, confirmation_hash,
                  claimed_at)
                 SELECT plan.cache_id, plan.plan_id, ?2, plan.expected_epoch,
                        plan.manifest_digest, plan.actor_scope_digest,
                        plan.confirmation_hash, ?5
                 FROM cache_gc_plans plan
                 JOIN cache_gc_generations generation
                   ON generation.generation_id = plan.generation_id
                  AND generation.cache_id = plan.cache_id
                 JOIN cache_gc_state state ON state.cache_id = plan.cache_id
                 JOIN cache_gc_heads head ON head.cache_id = state.cache_id
                 JOIN cache_gc_policies policy ON policy.cache_id = plan.cache_id
                 WHERE plan.plan_id = ?1 AND plan.applied_at IS NULL
                   AND plan.expires_at > ?5 AND plan.actor_scope_digest = ?3
                   AND plan.confirmation_hash = ?4
                   AND generation.state = 'complete'
                   AND generation.coverage_error_count = 0
                   AND head.current_mark_generation_id = generation.generation_id
                   AND state.destructive_enabled = 1
                   AND NOT EXISTS (
                     SELECT 1 FROM surface_placement_effective placement
                     LEFT JOIN bindings binding
                       ON binding.id = placement.binding_id
                     LEFT JOIN binding_write_revisions revision
                       ON revision.binding_id = placement.binding_id
                      AND revision.revision = placement.authority_observed_binding_write_revision
                     WHERE placement.cache_id = plan.cache_id
                       AND (COALESCE(binding.kind, '') = 'r2'
                         OR placement.requires_conditional_writes <> 1
                         OR COALESCE(revision.conditional_writes_supported, 0) <> 1))
                   AND state.epoch = plan.expected_epoch
                   AND state.epoch = generation.expected_epoch
                   AND state.root_generation = generation.root_generation
                   AND state.object_graph_generation = generation.object_graph_generation
                   AND state.inventory_generation = generation.inventory_generation
                   AND state.topology_generation = generation.topology_version
                   AND policy.resource_version = generation.gc_policy_version
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                     WHERE ticket.cache_id = plan.cache_id AND (
                       ticket.active_cache_slot = 1 OR
                       (ticket.state = 'completed'
                         AND ticket.covered_inventory_generation IS NULL)))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_retention_subscriptions subscription
                     LEFT JOIN registry_index registry
                       ON registry.registry_id = subscription.registry_id
                     LEFT JOIN cache_retention_refresh_heads refresh_head
                       ON refresh_head.subscription_id = subscription.id
                     LEFT JOIN cache_retention_refreshes refresh
                       ON refresh.refresh_id = refresh_head.current_refresh_id
                      AND refresh.subscription_id = subscription.id
                     WHERE subscription.cache_id = plan.cache_id
                       AND subscription.enabled = 1
                       AND subscription.retired_at IS NULL
                       AND (subscription.refresh_state <> 'fresh'
                         OR subscription.last_successful_revision IS NULL
                         OR registry.state <> 'fresh'
                         OR registry.last_indexed_commit IS NULL
                         OR subscription.last_successful_revision
                           <> registry.last_indexed_commit
                         OR refresh.refresh_id IS NULL
                         OR refresh.state <> 'complete'
                         OR refresh.registry_source_revision
                           <> registry.last_indexed_commit
                         OR refresh.registry_index_generation <> registry.generation
                         OR refresh.registry_index_digest <> registry.content_digest))
                   AND NOT EXISTS (SELECT 1
                     FROM cache_gc_generation_placements captured
                     LEFT JOIN surface_placements placement
                       ON placement.id = captured.placement_id
                      AND placement.cache_id = captured.cache_id
                     LEFT JOIN bindings binding
                       ON binding.id = placement.binding_id
                     WHERE captured.cache_id = plan.cache_id
                       AND captured.generation_id = plan.generation_id
                       AND (placement.id IS NULL
                         OR placement.resource_version
                           <> captured.placement_resource_version
                         OR placement.name <> captured.placement_name
                         OR placement.binding_id
                           <> captured.binding_id
                         OR COALESCE(binding.stable_id, '')
                           <> captured.binding_stable_id
                         OR binding.resource_version
                           <> captured.binding_resource_version
                         OR placement.prefix <> captured.prefix
                         OR placement.kind <> captured.placement_kind
                         OR placement.desired_state <> captured.desired_state
                         OR placement.write_spec_version
                           <> captured.write_spec_version
                         OR placement.requires_conditional_writes
                           <> captured.requires_conditional_writes))
                   AND NOT EXISTS (SELECT 1 FROM surface_placements placement
                     WHERE placement.cache_id = plan.cache_id
                       AND NOT EXISTS (SELECT 1
                         FROM cache_gc_generation_placements captured
                         WHERE captured.cache_id = plan.cache_id
                           AND captured.generation_id = plan.generation_id
                           AND captured.placement_id = placement.id))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_gc_plan_objects candidate
                     JOIN cache_objects object ON object.id = candidate.cache_object_id
                       AND object.cache_id = candidate.cache_id
                     WHERE candidate.cache_id = plan.cache_id
                       AND candidate.plan_id = plan.plan_id
                       AND (object.lifecycle_state <> 'active'
                         OR object.resource_version <> candidate.expected_object_version
                         OR object.unreferenced_since <> candidate.expected_unreferenced_since
                         OR EXISTS (SELECT 1 FROM cache_gc_marks mark
                           WHERE mark.cache_id = plan.cache_id
                             AND mark.generation_id = plan.generation_id
                             AND mark.cache_object_id = object.id)
                         OR EXISTS (SELECT 1 FROM cache_object_mutation_fences fence
                           WHERE fence.cache_id = plan.cache_id
                             AND fence.store_hash = object.store_hash
                             AND fence.state = 'active')))
                   AND NOT EXISTS (
                     SELECT 1 FROM cache_gc_plan_actions action
                     LEFT JOIN object_placements presence
                       ON presence.surface_object_id = action.surface_object_id
                      AND presence.placement_id = action.placement_id
                      AND presence.cache_id = action.cache_id
                     LEFT JOIN surface_placements placement
                       ON placement.id = action.placement_id
                      AND placement.cache_id = action.cache_id
                     LEFT JOIN bindings binding
                       ON binding.id = action.binding_id
                     LEFT JOIN binding_credential_revisions credential
                       ON credential.binding_id = action.binding_id
                      AND credential.purpose = 'delete'
                      AND credential.generation = action.delete_credential_generation
                     LEFT JOIN binding_credential_heads credential_head
                       ON credential_head.binding_id = action.binding_id
                      AND credential_head.purpose = 'delete'
                     WHERE action.cache_id = plan.cache_id
                       AND action.plan_id = plan.plan_id
                       AND (presence.surface_object_id IS NULL
                         OR placement.id IS NULL
                         OR binding.id IS NULL
                         OR credential.generation IS NULL
                         OR credential_head.current_generation IS NULL
                         OR placement.binding_id <> action.binding_id
                         OR binding.resource_version <> action.binding_resource_version
                         OR binding.kind <> 's3'
                         OR binding.is_instance_default <> 0
                         OR credential.validation_state <> 'valid'
                         OR credential_head.current_generation
                           <> action.delete_credential_generation
                         OR presence.observed_inventory_generation
                           <> action.expected_inventory_generation
                         OR NOT (presence.observed_hash = action.expected_hash
                           OR (presence.observed_hash IS NULL
                             AND action.expected_hash IS NULL))
                         OR NOT (presence.observed_size = action.expected_size
                           OR (presence.observed_size IS NULL
                             AND action.expected_size IS NULL))
                         OR NOT (presence.etag = action.expected_etag
                           OR (presence.etag IS NULL AND action.expected_etag IS NULL))
                         OR (presence.state NOT IN ('present', 'corrupt') AND NOT (
                           presence.state = 'deleting' AND EXISTS (
                             SELECT 1 FROM object_deletion_jobs existing
                             WHERE existing.surface_object_id = action.surface_object_id
                               AND existing.placement_id = action.placement_id
                               AND existing.active_slot = 1
                               AND existing.phase = action.phase
                               AND (existing.expected_etag = action.expected_etag
                                 OR (existing.expected_etag IS NULL
                                   AND action.expected_etag IS NULL))
                               AND (existing.expected_hash = action.expected_hash
                                 OR (existing.expected_hash IS NULL
                                   AND action.expected_hash IS NULL))
                               AND (existing.expected_size = action.expected_size
                                 OR (existing.expected_size IS NULL
                                   AND action.expected_size IS NULL))
                               AND existing.expected_inventory_generation
                                 = action.expected_inventory_generation)))))",
                vals![
                    input.plan_id,
                    input.claim_id,
                    input.actor_scope_digest,
                    input.confirmation_hash,
                    input.now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_gc_state
                 SET epoch = epoch + 1, epoch_owner_token = ?3,
                     object_graph_generation = object_graph_generation + 1,
                     destructive_enabled = 1,
                     resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND epoch = ?2
                   AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                     WHERE cache_id = ?1 AND plan_id = ?4 AND claim_id = ?3)",
                vals![cache_id, expected_epoch, input.claim_id, input.plan_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_objects SET lifecycle_state = 'tombstoned',
                   tombstoned_at = ?3, resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'
                   AND id IN (SELECT cache_object_id FROM cache_gc_plan_objects
                     WHERE cache_id = ?1 AND plan_id = ?2)
                   AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                     WHERE cache_id = ?1 AND plan_id = ?2 AND claim_id = ?4)",
                vals![cache_id, input.plan_id, input.now, input.claim_id],
            )
            .expecting(expected_object_rows),
            Statement::new(
                "UPDATE surface_objects SET lifecycle_state = 'tombstoned',
                   tombstoned_at = ?3, resource_version = resource_version + 1,
                   updated_at = ?3
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'
                   AND id IN (SELECT object.narinfo_surface_object_id
                     FROM cache_gc_plan_objects candidate
                     JOIN cache_objects object ON object.id = candidate.cache_object_id
                       AND object.cache_id = candidate.cache_id
                     WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2)",
                vals![cache_id, input.plan_id, input.now],
            )
            .expecting(expected_object_rows),
            Statement::new(
                "UPDATE surface_objects SET lifecycle_state = 'tombstoned',
                   tombstoned_at = ?3, resource_version = resource_version + 1,
                   updated_at = ?3
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'
                   AND id IN (SELECT DISTINCT object.nar_surface_object_id
                     FROM cache_gc_plan_objects candidate
                     JOIN cache_objects object ON object.id = candidate.cache_object_id
                       AND object.cache_id = candidate.cache_id
                     WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM cache_objects live
                     WHERE live.cache_id = ?1 AND live.nar_surface_object_id = surface_objects.id
                       AND live.lifecycle_state = 'active')",
                vals![cache_id, input.plan_id, input.now],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO topology_operations
                 (operation_id, operation_kind, authorization_scope_key,
                  control_permission, primary_target_kind, primary_target_stable_id,
                  primary_target_generation_key, primary_target_configuration_digest, state,
                  progress_current, progress_total, detail_json, created_at,
                  started_at, finished_at, resource_version)
                 SELECT ?1, 'cache_gc', COALESCE(cache.scope_key, 'instance'),
                        'cache.gc.execute', 'binary_cache', cache.stable_id,
                        cache.resource_version, plan.manifest_digest, ?4, 0, ?3,
                        '{}', ?5, ?6, ?6, 1
                 FROM binary_caches cache
                 JOIN cache_gc_plans plan ON plan.cache_id = cache.id
                   AND plan.plan_id = ?7
                 WHERE cache.id = ?2
                   AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                     WHERE cache_id = ?2 AND plan_id = ?7 AND claim_id = ?8)",
                vals![
                    input.operation_id,
                    cache_id,
                    action_count,
                    operation_state,
                    input.now,
                    operation_terminal_at,
                    input.plan_id,
                    input.claim_id
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO operation_secondary_targets
                 (operation_id, role, target_kind, stable_id,
                  authorization_scope_key, control_permission,
                  generation_key, configuration_digest)
                 SELECT ?1, 'generation', 'cache_gc_generation',
                        generation.generation_id, cache.scope_key, 'cache.gc.execute',
                        generation.expected_epoch,
                        plan.input_versions_digest
                 FROM cache_gc_plans plan
                 JOIN cache_gc_generations generation
                   ON generation.generation_id = plan.generation_id
                  AND generation.cache_id = plan.cache_id
                 JOIN binary_caches cache ON cache.id = plan.cache_id
                 WHERE plan.cache_id = ?2 AND plan.plan_id = ?3
                   AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                     WHERE cache_id = ?2 AND plan_id = ?3 AND claim_id = ?4)",
                vals![input.operation_id, cache_id, input.plan_id, input.claim_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_gc_plans SET applied_at = ?3, operation_id = ?4,
                   operation_target_kind = 'binary_cache',
                   operation_target_stable_id = (SELECT stable_id
                     FROM binary_caches WHERE id = ?1)
                 WHERE cache_id = ?1 AND plan_id = ?2 AND applied_at IS NULL
                   AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                     WHERE cache_id = ?1 AND plan_id = ?2 AND claim_id = ?5)",
                vals![
                    cache_id,
                    input.plan_id,
                    input.now,
                    input.operation_id,
                    input.claim_id
                ],
            )
            .expecting(1),
        ];

        for row in &actions {
            let action_id: String = row.get(0)?;
            let surface_object_id: i64 = row.get(1)?;
            let placement_id: i64 = row.get(2)?;
            let phase: String = row.get(3)?;
            let expected_etag: Option<String> = row.get(4)?;
            let expected_hash: Option<String> = row.get(5)?;
            let expected_size: Option<i64> = row.get(6)?;
            let expected_inventory_generation: i64 = row.get(7)?;
            let binding_id: i64 = row.get(8)?;
            let binding_resource_version: i64 = row.get(9)?;
            let delete_credential_generation: i64 = row.get(10)?;
            let dependency_count: i64 = row.get(12)?;
            let initial_state = if dependency_count == 0 {
                "pending"
            } else {
                "blocked"
            };
            statements.push(
                Statement::new(
                    "INSERT INTO object_deletion_jobs
                     (job_id, cache_id, originating_operation_id,
                      operation_target_kind, operation_target_stable_id,
                      surface_object_id, placement_id, phase, expected_etag,
                      expected_hash, expected_size, expected_inventory_generation,
                      binding_id, binding_resource_version,
                      delete_credential_generation,
                      state, active_slot, attempt_count, max_attempts,
                      confirmed_reclaimed_bytes, leaked_bytes, resource_version,
                      created_at)
                     SELECT ?1, ?2, ?3, 'binary_cache', cache.stable_id,
                            ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                            ?14, 1, 0, ?15, 0, 0, 1, ?16
                     FROM binary_caches cache
                     WHERE cache.id = ?2
                       AND EXISTS (SELECT 1 FROM cache_gc_apply_claims
                       WHERE cache_id = ?2 AND plan_id = ?17 AND claim_id = ?18)
                       AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs
                         WHERE surface_object_id = ?4 AND placement_id = ?5
                           AND active_slot = 1)",
                    vals![
                        action_id,
                        cache_id,
                        input.operation_id,
                        surface_object_id,
                        placement_id,
                        phase,
                        expected_etag,
                        expected_hash,
                        expected_size,
                        expected_inventory_generation,
                        binding_id,
                        binding_resource_version,
                        delete_credential_generation,
                        initial_state,
                        max_attempts,
                        input.now,
                        input.plan_id,
                        input.claim_id
                    ],
                )
                .unchecked(),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_action_jobs
                     (cache_id, plan_id, action_id, job_id,
                      surface_object_id, placement_id)
                     SELECT action.cache_id, action.plan_id, action.action_id,
                       existing.job_id, action.surface_object_id, action.placement_id
                     FROM cache_gc_plan_actions action
                     JOIN object_deletion_jobs existing
                       ON existing.surface_object_id = action.surface_object_id
                      AND existing.placement_id = action.placement_id
                      AND existing.active_slot = 1
                      AND existing.phase = action.phase
                      AND (existing.expected_etag = action.expected_etag
                        OR (existing.expected_etag IS NULL
                          AND action.expected_etag IS NULL))
                      AND (existing.expected_hash = action.expected_hash
                        OR (existing.expected_hash IS NULL
                          AND action.expected_hash IS NULL))
                      AND (existing.expected_size = action.expected_size
                        OR (existing.expected_size IS NULL
                          AND action.expected_size IS NULL))
                      AND existing.expected_inventory_generation
                        = action.expected_inventory_generation
                      AND existing.binding_id = action.binding_id
                      AND existing.binding_resource_version = action.binding_resource_version
                      AND existing.delete_credential_generation
                        = action.delete_credential_generation
                     WHERE action.cache_id = ?1 AND action.plan_id = ?2
                       AND action.action_id = ?3",
                    vals![cache_id, input.plan_id, action_id],
                )
                .expecting(1),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO cache_gc_operation_jobs
                     (operation_id, cache_id, operation_target_kind,
                      operation_target_stable_id, plan_id, job_id)
                     SELECT ?4, link.cache_id, 'binary_cache', cache.stable_id,
                            link.plan_id, link.job_id
                     FROM cache_gc_action_jobs link
                     JOIN binary_caches cache ON cache.id = link.cache_id
                     WHERE link.cache_id = ?1 AND link.plan_id = ?2
                       AND link.action_id = ?3",
                    vals![cache_id, input.plan_id, action_id, input.operation_id],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "UPDATE object_placements SET state = 'deleting'
                 WHERE cache_id = ?1 AND state IN ('present', 'corrupt')
                   AND EXISTS (SELECT 1 FROM cache_gc_plan_actions action
                     WHERE action.cache_id = ?1 AND action.plan_id = ?2
                       AND action.surface_object_id = object_placements.surface_object_id
                       AND action.placement_id = object_placements.placement_id)",
                vals![cache_id, input.plan_id],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "INSERT INTO cache_gc_apply_assertions
                 (cache_id, plan_id, claim_id, ok, asserted_at)
                 VALUES (?1, ?2, ?3,
                   CASE WHEN EXISTS (SELECT 1 FROM cache_gc_state
                     WHERE cache_id = ?1 AND epoch = ?4 + 1
                       AND epoch_owner_token = ?3)
                     AND EXISTS (SELECT 1 FROM cache_gc_plans
                       WHERE cache_id = ?1 AND plan_id = ?2
                         AND operation_id = ?5 AND applied_at = ?6)
                     AND (SELECT COUNT(*) FROM cache_gc_plan_objects
                       WHERE cache_id = ?1 AND plan_id = ?2)
                       = (SELECT COUNT(*) FROM cache_objects object
                         JOIN cache_gc_plan_objects candidate
                           ON candidate.cache_object_id = object.id
                          AND candidate.cache_id = object.cache_id
                         WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2
                           AND object.lifecycle_state = 'tombstoned'
                           AND object.tombstoned_at = ?6)
                     AND (SELECT COUNT(*) FROM cache_gc_plan_actions
                       WHERE cache_id = ?1 AND plan_id = ?2)
                       = (SELECT COUNT(*) FROM cache_gc_action_jobs
                         WHERE cache_id = ?1 AND plan_id = ?2)
                     AND (SELECT COUNT(DISTINCT job_id)
                       FROM cache_gc_action_jobs
                       WHERE cache_id = ?1 AND plan_id = ?2)
                       = (SELECT COUNT(*) FROM cache_gc_operation_jobs
                         WHERE cache_id = ?1 AND plan_id = ?2
                           AND operation_id = ?5)
                     AND NOT EXISTS (SELECT 1 FROM cache_gc_action_jobs link
                       JOIN object_deletion_jobs job ON job.job_id = link.job_id
                         AND job.cache_id = link.cache_id
                       JOIN object_placements presence
                         ON presence.surface_object_id = link.surface_object_id
                        AND presence.placement_id = link.placement_id
                       WHERE link.cache_id = ?1 AND link.plan_id = ?2
                         AND (job.active_slot <> 1 OR presence.state <> 'deleting'))
                   THEN 1 ELSE 0 END, ?6)",
                vals![
                    cache_id,
                    input.plan_id,
                    input.claim_id,
                    expected_epoch,
                    input.operation_id,
                    input.now
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await?;
        Ok(input.operation_id.clone())
    }

    /// Claims one due deletion job after checking dependency and NAR refcount safety.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale version, an exhausted/not-due job,
    /// unsatisfied dependencies, a live placement-scoped NAR reference, or
    /// database failure.
    pub async fn claim_cache_gc_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
        expected_version: i64,
        request_id: &str,
        now: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_stable_key(job_id, "cache GC deletion job id")?;
        validate_stable_key(request_id, "cache GC deletion request id")?;
        let capacity = Statement::new(
            "UPDATE cache_gc_deletion_capacity SET running_count = running_count + 1
             WHERE cache_id = ?1
               AND running_count < (SELECT deletion_concurrency
                 FROM cache_gc_policies WHERE cache_id = ?1)",
            vals![cache_id],
        )
        .expecting(1);
        let statement = Statement::new(
            "UPDATE object_deletion_jobs SET state = 'running',
               attempt_count = attempt_count + 1, next_attempt_at = NULL,
               error_class = NULL, error = NULL, started_at = COALESCE(started_at, ?4),
               finished_at = NULL,
               resource_version = resource_version + 1
             WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?3
               AND state IN ('pending', 'failed', 'blocked')
               AND active_slot = 1 AND attempt_count < max_attempts
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?4)
               AND NOT EXISTS (SELECT 1 FROM cache_gc_action_jobs link
                 JOIN cache_gc_action_dependencies dependency
                   ON dependency.cache_id = link.cache_id
                  AND dependency.plan_id = link.plan_id
                  AND dependency.action_id = link.action_id
                 JOIN cache_gc_action_jobs prior_link
                   ON prior_link.cache_id = dependency.cache_id
                  AND prior_link.plan_id = dependency.plan_id
                  AND prior_link.action_id = dependency.prerequisite_action_id
                 JOIN object_deletion_jobs prior ON prior.job_id = prior_link.job_id
                  AND prior.cache_id = prior_link.cache_id
                 WHERE link.cache_id = ?1 AND link.job_id = ?2
                   AND prior.state <> 'succeeded')
               AND (phase <> 'nar' OR NOT EXISTS (
                 SELECT 1 FROM cache_objects object
                 JOIN object_placements narinfo_presence
                   ON narinfo_presence.surface_object_id
                     = object.narinfo_surface_object_id
                  AND narinfo_presence.placement_id
                     = object_deletion_jobs.placement_id
                 WHERE object.cache_id = ?1
                   AND object.nar_surface_object_id
                     = object_deletion_jobs.surface_object_id
                   AND narinfo_presence.state <> 'missing'))",
            vals![cache_id, job_id, expected_version, now],
        )
        .expecting(1);
        let receipt = Statement::new(
            "INSERT INTO object_deletion_attempt_receipts
             (request_id, cache_id, job_id, attempt_number, placement_id,
              surface_object_id, object_key, expected_etag, expected_hash,
              expected_size, expected_inventory_generation, binding_id,
              binding_resource_version, delete_credential_generation,
              state, requested_at)
             SELECT ?4, job.cache_id, job.job_id, job.attempt_count,
                    job.placement_id, job.surface_object_id, object.object_key,
                    job.expected_etag, job.expected_hash, job.expected_size,
                    job.expected_inventory_generation, job.binding_id,
                    job.binding_resource_version, job.delete_credential_generation,
                    'requested', ?5
             FROM object_deletion_jobs job
             JOIN surface_objects object ON object.id = job.surface_object_id
               AND object.cache_id = job.cache_id
             WHERE job.cache_id = ?1 AND job.job_id = ?2
               AND job.resource_version = ?3 + 1 AND job.state = 'running'",
            vals![cache_id, job_id, expected_version, request_id, now],
        )
        .expecting(1);
        let operation = Statement::new(
            "UPDATE topology_operations SET state = 'running',
               started_at = COALESCE(started_at, ?3),
               resource_version = resource_version + 1
             WHERE state IN ('pending', 'running')
               AND operation_id IN (SELECT link.operation_id
                 FROM cache_gc_operation_jobs link
                 JOIN object_deletion_jobs job ON job.job_id = link.job_id
                   AND job.cache_id = link.cache_id
                 WHERE link.cache_id = ?1 AND link.job_id = ?2
                   AND job.state = 'running')",
            vals![cache_id, job_id, now],
        )
        .unchecked();
        self.backend
            .checked_batch(&[capacity, statement, receipt, operation])
            .await?;
        self.object_deletion_job(cache_id, job_id)
            .await?
            .context("claimed cache GC deletion job disappeared")
    }

    /// Records an exact successful physical deletion and confirmed bytes once.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/non-running job, changed placement evidence,
    /// or database failure.
    pub async fn succeed_cache_gc_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
        expected_version: i64,
        request_id: &str,
        finished_at: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_stable_key(job_id, "cache GC deletion job id")?;
        validate_stable_key(request_id, "cache GC deletion request id")?;
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM object_deletion_jobs job
                 JOIN object_placements presence
                   ON presence.surface_object_id = job.surface_object_id
                  AND presence.placement_id = job.placement_id
                 JOIN object_deletion_attempt_receipts receipt
                   ON receipt.job_id = job.job_id AND receipt.cache_id = job.cache_id
                 WHERE job.cache_id = ?1 AND job.job_id = ?2
                   AND job.resource_version = ?3 + 1
                   AND job.state = 'succeeded' AND job.finished_at = ?4
                   AND presence.state = 'missing' AND presence.observed_at = ?4
                   AND receipt.request_id = ?5 AND receipt.state = 'finalized'
                   AND receipt.outcome IN ('deleted', 'not_found')",
                &vals![cache_id, job_id, expected_version, finished_at, request_id],
            )
            .await?
            .is_some()
        {
            return self
                .object_deletion_job(cache_id, job_id)
                .await?
                .context("successful cache GC deletion job disappeared");
        }
        let statements = vec![
            Statement::new(
                "UPDATE object_placements SET state = 'missing', observed_at = ?4
                 WHERE cache_id = ?1 AND state = 'deleting'
                   AND surface_object_id = (SELECT surface_object_id
                     FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2
                       AND state = 'running' AND resource_version = ?3)
                   AND placement_id = (SELECT placement_id
                     FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2)
                   AND observed_inventory_generation = (SELECT expected_inventory_generation
                     FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2)
                   AND (observed_hash = (SELECT expected_hash FROM object_deletion_jobs
                         WHERE cache_id = ?1 AND job_id = ?2)
                     OR (observed_hash IS NULL AND (SELECT expected_hash
                         FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2) IS NULL))
                   AND (observed_size = (SELECT expected_size FROM object_deletion_jobs
                         WHERE cache_id = ?1 AND job_id = ?2)
                     OR (observed_size IS NULL AND (SELECT expected_size
                         FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2) IS NULL))
                   AND (etag = (SELECT expected_etag FROM object_deletion_jobs
                         WHERE cache_id = ?1 AND job_id = ?2)
                     OR (etag IS NULL AND (SELECT expected_etag
                         FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2) IS NULL))
                   AND EXISTS (SELECT 1 FROM object_deletion_attempt_receipts receipt
                     WHERE receipt.request_id = ?5 AND receipt.cache_id = ?1
                       AND receipt.job_id = ?2 AND receipt.state = 'responded'
                       AND receipt.outcome IN ('deleted', 'not_found'))",
                vals![cache_id, job_id, expected_version, finished_at, request_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE object_deletion_jobs SET state = 'succeeded',
                   active_slot = NULL,
                   confirmed_reclaimed_bytes = COALESCE(expected_size, 0),
                   finished_at = ?4, resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?3
                   AND state = 'running' AND active_slot = 1
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.surface_object_id = object_deletion_jobs.surface_object_id
                       AND presence.placement_id = object_deletion_jobs.placement_id
                       AND presence.state = 'missing' AND presence.observed_at = ?4)
                   AND EXISTS (SELECT 1 FROM object_deletion_attempt_receipts receipt
                     WHERE receipt.request_id = ?5 AND receipt.cache_id = ?1
                       AND receipt.job_id = ?2 AND receipt.state = 'responded'
                       AND receipt.outcome IN ('deleted', 'not_found'))",
                vals![cache_id, job_id, expected_version, finished_at, request_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_gc_deletion_capacity
                 SET running_count = running_count - 1
                 WHERE cache_id = ?1 AND running_count > 0
                   AND EXISTS (SELECT 1 FROM object_deletion_jobs
                     WHERE cache_id = ?1 AND job_id = ?2
                       AND state = 'succeeded' AND resource_version = ?3 + 1
                       AND finished_at = ?4)",
                vals![cache_id, job_id, expected_version, finished_at],
            )
            .expecting(1),
            Statement::new(
                "UPDATE object_deletion_attempt_receipts
                 SET state = 'finalized', finalized_at = ?4
                 WHERE request_id = ?5 AND cache_id = ?1 AND job_id = ?2
                   AND state = 'responded'
                   AND outcome IN ('deleted', 'not_found')",
                vals![cache_id, job_id, expected_version, finished_at, request_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE object_deletion_jobs SET state = 'pending',
                   next_attempt_at = NULL, resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND state = 'blocked' AND active_slot = 1
                   AND EXISTS (SELECT 1 FROM cache_gc_action_jobs link
                     JOIN cache_gc_action_dependencies dependency
                       ON dependency.cache_id = link.cache_id
                      AND dependency.plan_id = link.plan_id
                      AND dependency.action_id = link.action_id
                     WHERE link.cache_id = ?1
                       AND link.job_id = object_deletion_jobs.job_id)
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_action_jobs link
                     JOIN cache_gc_action_dependencies dependency
                       ON dependency.cache_id = link.cache_id
                      AND dependency.plan_id = link.plan_id
                      AND dependency.action_id = link.action_id
                     JOIN cache_gc_action_jobs prior_link
                       ON prior_link.cache_id = dependency.cache_id
                      AND prior_link.plan_id = dependency.plan_id
                      AND prior_link.action_id = dependency.prerequisite_action_id
                     JOIN object_deletion_jobs prior
                       ON prior.job_id = prior_link.job_id
                      AND prior.cache_id = prior_link.cache_id
                     WHERE link.cache_id = ?1
                       AND link.job_id = object_deletion_jobs.job_id
                       AND prior.state <> 'succeeded')",
                vals![cache_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE topology_operations SET
                   progress_current = (SELECT COUNT(DISTINCT link.job_id)
                     FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.state IN ('succeeded', 'abandoned')),
                   state = CASE WHEN NOT EXISTS (SELECT 1
                     FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1)
                     THEN CASE WHEN EXISTS (SELECT 1
                       FROM cache_gc_operation_jobs link
                       JOIN object_deletion_jobs job ON job.job_id = link.job_id
                         AND job.cache_id = link.cache_id
                       WHERE link.operation_id = topology_operations.operation_id
                         AND job.state = 'abandoned')
                       THEN 'failed' ELSE 'succeeded' END
                     ELSE 'running' END,
                   error = CASE WHEN NOT EXISTS (SELECT 1
                     FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1)
                     AND EXISTS (SELECT 1
                       FROM cache_gc_operation_jobs link
                       JOIN object_deletion_jobs job ON job.job_id = link.job_id
                         AND job.cache_id = link.cache_id
                       WHERE link.operation_id = topology_operations.operation_id
                         AND job.state = 'abandoned')
                     THEN 'one or more physical deletions were abandoned'
                     ELSE NULL END,
                   started_at = COALESCE(started_at, ?3),
                   finished_at = CASE WHEN NOT EXISTS (
                     SELECT 1 FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1) THEN ?3 ELSE finished_at END,
                   resource_version = resource_version + 1
                 WHERE operation_id IN (
                   SELECT operation_id FROM cache_gc_operation_jobs
                   WHERE cache_id = ?1 AND job_id = ?2)",
                vals![cache_id, job_id, finished_at],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await?;
        self.object_deletion_job(cache_id, job_id)
            .await?
            .context("successful cache GC deletion job disappeared")
    }

    /// Records a retryable deletion failure without changing presence evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid error data, a stale/non-running job, or
    /// database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn fail_cache_gc_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
        expected_version: i64,
        request_id: &str,
        error_class: &str,
        error: &str,
        next_attempt_at: i64,
        failed_at: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_stable_key(job_id, "cache GC deletion job id")?;
        validate_stable_key(request_id, "cache GC deletion request id")?;
        if error_class.trim().is_empty() || error.trim().is_empty() {
            bail!("cache GC deletion failure requires a class and detail");
        }
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM object_deletion_jobs job
                 JOIN object_deletion_attempt_receipts receipt
                   ON receipt.job_id = job.job_id AND receipt.cache_id = job.cache_id
                 WHERE job.cache_id = ?1 AND job.job_id = ?2
                   AND job.resource_version = ?3 + 1
                   AND job.state IN ('failed', 'blocked')
                   AND receipt.request_id = ?4 AND receipt.state = 'finalized'
                   AND receipt.outcome IN ('precondition_failed', 'backend_error')",
                &vals![cache_id, job_id, expected_version, request_id],
            )
            .await?
            .is_some()
        {
            return self
                .object_deletion_job(cache_id, job_id)
                .await?
                .context("failed cache GC deletion job disappeared");
        }
        let statement = Statement::new(
            "UPDATE object_deletion_jobs SET
               state = CASE WHEN attempt_count >= max_attempts
                 THEN 'blocked' ELSE 'failed' END,
               next_attempt_at = CASE WHEN attempt_count >= max_attempts
                 THEN NULL ELSE ?5 END,
               error_class = ?6, error = ?7,
               finished_at = ?8, resource_version = resource_version + 1
             WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?3
               AND state = 'running' AND active_slot = 1
               AND EXISTS (SELECT 1 FROM object_deletion_attempt_receipts receipt
                 WHERE receipt.request_id = ?4 AND receipt.cache_id = ?1
                   AND receipt.job_id = ?2 AND receipt.state = 'responded'
                   AND receipt.outcome IN ('precondition_failed', 'backend_error')
                   AND receipt.error_class = ?6 AND receipt.response_detail = ?7)",
            vals![
                cache_id,
                job_id,
                expected_version,
                request_id,
                next_attempt_at,
                error_class,
                error,
                failed_at
            ],
        )
        .expecting(1);
        let receipt = Statement::new(
            "UPDATE object_deletion_attempt_receipts
             SET state = 'finalized', finalized_at = ?5
             WHERE request_id = ?4 AND cache_id = ?1 AND job_id = ?2
               AND state = 'responded'
               AND outcome IN ('precondition_failed', 'backend_error')",
            vals![cache_id, job_id, expected_version, request_id, failed_at],
        )
        .expecting(1);
        let operation = Statement::new(
            "UPDATE topology_operations SET state = 'failed', error = ?3,
               finished_at = ?4, resource_version = resource_version + 1
             WHERE operation_id IN (SELECT operation_id
               FROM cache_gc_operation_jobs WHERE cache_id = ?1 AND job_id = ?2)
               AND EXISTS (SELECT 1 FROM object_deletion_jobs
                 WHERE cache_id = ?1 AND job_id = ?2 AND state = 'blocked')
               AND state = 'running'",
            vals![cache_id, job_id, error, failed_at],
        )
        .unchecked();
        let capacity = Statement::new(
            "UPDATE cache_gc_deletion_capacity
             SET running_count = running_count - 1
             WHERE cache_id = ?1 AND running_count > 0
               AND EXISTS (SELECT 1 FROM object_deletion_jobs
                 WHERE cache_id = ?1 AND job_id = ?2
                   AND state IN ('failed', 'blocked')
                   AND resource_version = ?3 + 1 AND finished_at = ?4)",
            vals![cache_id, job_id, expected_version, failed_at],
        )
        .expecting(1);
        self.backend
            .checked_batch(&[statement, capacity, receipt, operation])
            .await?;
        self.object_deletion_job(cache_id, job_id)
            .await?
            .context("failed cache GC deletion job disappeared")
    }

    /// Requeues a failed job without discarding its placement evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/non-failed or exhausted job, or database
    /// failure.
    pub async fn retry_cache_gc_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
        expected_version: i64,
        idempotency_key: &str,
        now: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_stable_key(job_id, "cache GC deletion job id")?;
        if idempotency_key.is_empty() || idempotency_key.len() > 128 {
            bail!("cache GC retry idempotency key is invalid");
        }
        if let Some(existing) = self
            .backend
            .query_opt(
                "SELECT expected_resource_version FROM cache_gc_retry_requests
                 WHERE cache_id = ?1 AND job_id = ?2 AND idempotency_key = ?3",
                &vals![cache_id, job_id, idempotency_key],
            )
            .await?
        {
            if existing.get::<i64>(0)? != expected_version {
                bail!("cache GC retry idempotency key was reused with another version");
            }
            return self
                .object_deletion_job(cache_id, job_id)
                .await?
                .context("idempotently retried cache GC deletion job disappeared");
        }
        let statements = vec![
            Statement::new(
                "UPDATE object_deletion_jobs SET state = 'pending',
               next_attempt_at = ?4, error_class = NULL, error = NULL,
               finished_at = NULL, resource_version = resource_version + 1
             WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?3
               AND state = 'failed' AND active_slot = 1
               AND attempt_count < max_attempts",
                vals![cache_id, job_id, expected_version, now],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO cache_gc_retry_requests
             (cache_id, job_id, idempotency_key, expected_resource_version,
              resulting_resource_version, requested_at)
             SELECT ?1, ?2, ?3, ?4, ?4 + 1, ?5
             FROM object_deletion_jobs
             WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?4 + 1",
                vals![cache_id, job_id, idempotency_key, expected_version, now],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await?;
        self.object_deletion_job(cache_id, job_id)
            .await?
            .context("retried cache GC deletion job disappeared")
    }

    /// Applies a separately reviewed abandonment and records only possible leaked bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/terminal job or database failure.
    pub async fn abandon_cache_gc_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
        expected_version: i64,
        abandoned_at: i64,
    ) -> Result<ObjectDeletionJobRecord> {
        validate_stable_key(job_id, "cache GC deletion job id")?;
        let statements = vec![
            Statement::new(
                "UPDATE object_deletion_jobs SET state = 'abandoned',
                   active_slot = NULL, leaked_bytes = COALESCE(expected_size, 0),
                   next_attempt_at = NULL, finished_at = ?4,
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND job_id = ?2 AND resource_version = ?3
                   AND state IN ('pending', 'failed', 'blocked')
                   AND active_slot = 1",
                vals![cache_id, job_id, expected_version, abandoned_at],
            )
            .expecting(1),
            Statement::new(
                "UPDATE object_deletion_jobs SET state = 'blocked',
                   error_class = 'dependency_abandoned',
                   error = 'a prerequisite deletion was abandoned',
                   resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND active_slot = 1
                   AND job_id IN (SELECT dependent.job_id
                     FROM cache_gc_action_jobs abandoned_link
                     JOIN cache_gc_action_dependencies dependency
                       ON dependency.cache_id = abandoned_link.cache_id
                      AND dependency.plan_id = abandoned_link.plan_id
                      AND dependency.prerequisite_action_id = abandoned_link.action_id
                     JOIN cache_gc_action_jobs dependent
                       ON dependent.cache_id = dependency.cache_id
                      AND dependent.plan_id = dependency.plan_id
                      AND dependent.action_id = dependency.action_id
                     WHERE abandoned_link.cache_id = ?1
                       AND abandoned_link.job_id = ?2)",
                vals![cache_id, job_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE topology_operations SET
                   progress_current = (SELECT COUNT(DISTINCT link.job_id)
                     FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.state IN ('succeeded', 'abandoned')),
                   state = CASE WHEN NOT EXISTS (
                     SELECT 1 FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1) THEN 'failed' ELSE 'running' END,
                   error = CASE WHEN NOT EXISTS (
                     SELECT 1 FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1)
                     THEN 'one or more physical deletions were abandoned'
                     ELSE error END,
                   started_at = COALESCE(started_at, ?3),
                   finished_at = CASE WHEN NOT EXISTS (
                     SELECT 1 FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.operation_id = topology_operations.operation_id
                       AND job.active_slot = 1) THEN ?3 ELSE finished_at END,
                   resource_version = resource_version + 1
                 WHERE operation_id IN (
                   SELECT operation_id FROM cache_gc_operation_jobs
                   WHERE cache_id = ?1 AND job_id = ?2)",
                vals![cache_id, job_id, abandoned_at],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await?;
        self.object_deletion_job(cache_id, job_id)
            .await?
            .context("abandoned cache GC deletion job disappeared")
    }

    /// Creates or replaces one registry-derived retention subscription.
    ///
    /// The selector and its digest are an inseparable immutable input to each
    /// refresh. Changing or disabling a subscription advances the same cache
    /// root epoch used by mark and apply, so an already-reviewed plan cannot
    /// cross the configuration transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical selector, digest mismatch,
    /// negative grace, stale subscription or cache versions, missing
    /// resources, or database failure.
    pub async fn set_cache_retention_subscription_topology(
        &self,
        input: &SetCacheRetentionSubscriptionTopology,
    ) -> Result<CacheRetentionSubscriptionRecord> {
        validate_stable_key(&input.mutation_id, "retention subscription mutation id")?;
        if input.removal_grace_secs < 0 || input.expected_cache_epoch < 0 {
            bail!("retention subscription grace and cache epoch cannot be negative");
        }
        let selector: serde_json::Value =
            serde_json::from_str(&input.selector_json).context("parsing retention selector")?;
        if !selector.is_object() || serde_json::to_string(&selector)? != input.selector_json {
            bail!("retention selector must be a canonical JSON object");
        }
        let computed_digest = hex::encode(Sha256::digest(input.selector_json.as_bytes()));
        if computed_digest != input.selector_digest {
            bail!("retention selector digest does not match its canonical document");
        }
        let (subscription, resulting_version) =
            if let Some(expected_version) = input.expected_resource_version {
                if expected_version <= 0 {
                    bail!("retention subscription resource version must be positive");
                }
                (
                    Statement::new(
                        "UPDATE cache_retention_subscriptions
                     SET selector_json = ?3, selector_digest = ?4,
                         removal_grace_secs = ?5,
                         exposure_acknowledged_at = ?6, enabled = ?7,
                         refresh_state = 'stale', refresh_error = NULL,
                         retired_at = CASE WHEN ?7 = 1 THEN NULL
                           ELSE COALESCE(retired_at, ?8) END,
                         resource_version = resource_version + 1,
                         updated_at = ?8
                     WHERE cache_id = ?1 AND registry_id = ?2
                       AND resource_version = ?9",
                        vals![
                            input.cache_id,
                            input.registry_id,
                            input.selector_json,
                            input.selector_digest,
                            input.removal_grace_secs,
                            input.exposure_acknowledged_at,
                            input.enabled,
                            input.now,
                            expected_version
                        ],
                    )
                    .expecting(1),
                    expected_version + 1,
                )
            } else {
                (
                    Statement::new(
                        "INSERT INTO cache_retention_subscriptions
                     (cache_id, registry_id, selector_json, selector_digest,
                      removal_grace_secs, exposure_acknowledged_at, enabled,
                      refresh_state, retired_at, resource_version,
                      created_at, updated_at)
                     SELECT cache.id, registry.id, ?3, ?4, ?5, ?6, ?7,
                            'stale', CASE WHEN ?7 = 1 THEN NULL ELSE ?8 END,
                            1, ?8, ?8
                     FROM binary_caches cache CROSS JOIN registries registry
                     WHERE cache.id = ?1 AND registry.id = ?2
                       AND cache.deleted_at IS NULL",
                        vals![
                            input.cache_id,
                            input.registry_id,
                            input.selector_json,
                            input.selector_digest,
                            input.removal_grace_secs,
                            input.exposure_acknowledged_at,
                            input.enabled,
                            input.now
                        ],
                    )
                    .expecting(1),
                    1,
                )
            };
        let statements = vec![
            subscription,
            epoch_update_statement(
                input.cache_id,
                input.expected_cache_epoch,
                &input.mutation_id,
                "root_generation = root_generation + 1",
            ),
            epoch_assertion_statement(
                &input.mutation_id,
                input.cache_id,
                input.expected_cache_epoch,
                "root",
                input.now,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_retention_subscriptions WHERE cache_id = {} AND registry_id = {} AND resource_version = {})",
                    input.cache_id, input.registry_id, resulting_version
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await?;
        self.cache_retention_subscription_topology(input.cache_id, input.registry_id)
            .await?
            .context("retention subscription disappeared")
    }

    /// Returns one cache/registry retention subscription and its current head.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_retention_subscription_topology(
        &self,
        cache_id: i64,
        registry_id: i64,
    ) -> Result<Option<CacheRetentionSubscriptionRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {RETENTION_SUBSCRIPTION_COLUMNS}
                     FROM cache_retention_subscriptions subscription
                     LEFT JOIN cache_retention_refresh_heads head
                       ON head.subscription_id = subscription.id
                     WHERE subscription.cache_id = ?1
                       AND subscription.registry_id = ?2"
                ),
                &vals![cache_id, registry_id],
            )
            .await?
            .map(|row| row_to_cache_retention_subscription(&row))
            .transpose()
    }

    /// Lists retention subscriptions owned by one cache.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_cache_retention_subscriptions_topology(
        &self,
        cache_id: i64,
    ) -> Result<Vec<CacheRetentionSubscriptionRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {RETENTION_SUBSCRIPTION_COLUMNS}
                     FROM cache_retention_subscriptions subscription
                     LEFT JOIN cache_retention_refresh_heads head
                       ON head.subscription_id = subscription.id
                     WHERE subscription.cache_id = ?1
                     ORDER BY subscription.registry_id"
                ),
                &vals![cache_id],
            )
            .await?
            .iter()
            .map(row_to_cache_retention_subscription)
            .collect()
    }

    /// Lists retention subscriptions supplied by one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_registry_retention_subscriptions_topology(
        &self,
        registry_id: i64,
    ) -> Result<Vec<CacheRetentionSubscriptionRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {RETENTION_SUBSCRIPTION_COLUMNS}
                     FROM cache_retention_subscriptions subscription
                     LEFT JOIN cache_retention_refresh_heads head
                       ON head.subscription_id = subscription.id
                     WHERE subscription.registry_id = ?1
                     ORDER BY subscription.cache_id"
                ),
                &vals![registry_id],
            )
            .await?
            .iter()
            .map(row_to_cache_retention_subscription)
            .collect()
    }

    /// Retires a retention subscription while preserving its current head for grace.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale subscription/cache epoch, invalid identity,
    /// or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn retire_cache_retention_subscription_topology(
        &self,
        subscription_id: i64,
        cache_id: i64,
        expected_resource_version: i64,
        expected_cache_epoch: i64,
        mutation_id: &str,
        retired_at: i64,
    ) -> Result<()> {
        validate_stable_key(mutation_id, "retention subscription retirement id")?;
        let statements = vec![
            Statement::new(
                "UPDATE cache_retention_subscriptions
                 SET enabled = 0, retired_at = ?4, refresh_state = 'stale',
                     refresh_error = NULL,
                     resource_version = resource_version + 1, updated_at = ?4
                 WHERE id = ?1 AND cache_id = ?2 AND resource_version = ?3
                   AND retired_at IS NULL",
                vals![
                    subscription_id,
                    cache_id,
                    expected_resource_version,
                    retired_at
                ],
            )
            .expecting(1),
            epoch_update_statement(
                cache_id,
                expected_cache_epoch,
                mutation_id,
                "root_generation = root_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_cache_epoch,
                "root",
                retired_at,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_retention_subscriptions WHERE id = {} AND cache_id = {} AND retired_at = {})",
                    subscription_id, cache_id, retired_at
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Begins an immutable, unreachable retention refresh generation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a stale/retired subscription, a
    /// stale cache epoch, or database failure.
    pub async fn begin_retention_refresh_topology(
        &self,
        input: &BeginRetentionRefresh,
    ) -> Result<()> {
        validate_stable_key(&input.refresh_id, "retention refresh id")?;
        if input.expected_subscription_version <= 0
            || input.expected_cache_epoch < 0
            || input.expected_reason_count < 0
            || input.selector_digest.is_empty()
            || input.registry_source_revision.is_empty()
            || input.registry_index_generation <= 0
            || input.registry_index_digest.is_empty()
        {
            bail!("retention refresh has invalid versions, count, or digests");
        }
        let statements = vec![
            Statement::new(
                "INSERT INTO cache_retention_refreshes
                 (refresh_id, subscription_id, cache_id, registry_id,
                  parent_refresh_id, expected_parent_refresh_id,
                  expected_subscription_version, expected_cache_epoch,
                  selector_digest, registry_source_revision,
                  registry_index_generation, registry_index_digest, state,
                  expected_reason_count, actual_reason_count, started_at)
                 SELECT ?1, sub.id, sub.cache_id, sub.registry_id,
                        head.current_refresh_id, head.current_refresh_id,
                        sub.resource_version, state.epoch, ?5, ?6, ?7, ?8, 'building',
                        ?9, 0, ?10
                 FROM cache_retention_subscriptions sub
                 LEFT JOIN cache_retention_refresh_heads head
                   ON head.subscription_id = sub.id
                 JOIN cache_gc_state state ON state.cache_id = sub.cache_id
                 JOIN registry_index idx ON idx.registry_id = sub.registry_id
                 WHERE sub.id = ?2 AND sub.resource_version = ?3
                   AND state.epoch = ?4 AND sub.selector_digest = ?5
                   AND idx.last_indexed_commit = ?6
                   AND idx.generation = ?7 AND idx.content_digest = ?8
                   AND sub.enabled = 1 AND sub.retired_at IS NULL",
                vals![
                    input.refresh_id,
                    input.subscription_id,
                    input.expected_subscription_version,
                    input.expected_cache_epoch,
                    input.selector_digest,
                    input.registry_source_revision,
                    input.registry_index_generation,
                    input.registry_index_digest,
                    input.expected_reason_count,
                    input.started_at
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_retention_subscriptions
                 SET refresh_state = 'refreshing', refresh_error = NULL,
                     updated_at = ?3
                 WHERE id = ?1 AND resource_version = ?2
                   AND EXISTS (SELECT 1 FROM cache_retention_refreshes
                     WHERE refresh_id = ?4 AND subscription_id = ?1
                       AND state = 'building')",
                vals![
                    input.subscription_id,
                    input.expected_subscription_version,
                    input.started_at,
                    input.refresh_id
                ],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Stages one immutable provenance-bearing reason under a building refresh.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or cross-registry provenance, an
    /// inactive refresh, duplicate identity, or database failure.
    pub async fn stage_retention_refresh_reason_topology(
        &self,
        refresh_id: &str,
        input: &RetentionRefreshReason,
    ) -> Result<()> {
        validate_stable_key(refresh_id, "retention refresh id")?;
        validate_stable_key(&input.reason_id, "retention reason id")?;
        validate_store_hash(&input.store_hash)?;
        if input.reason_key.is_empty()
            || input.reason_key.len() > 255
            || input.source_ref.is_empty()
            || input.source_ref.len() > 255
        {
            bail!("retention reason key and source reference must contain 1 through 255 bytes");
        }
        let valid_shape = match input.source_kind.as_str() {
            "registry_catalog" => {
                input.release_id.is_none()
                    && input.release_snapshot_id.is_none()
                    && input.channel_id.is_none()
                    && input.partition_bucket.is_none()
            }
            "release" => {
                input.release_id.is_some()
                    && input.release_snapshot_id.is_some()
                    && input.channel_id.is_none()
                    && input.partition_bucket.is_none()
            }
            "channel" => {
                input.release_id.is_some()
                    && input.release_snapshot_id.is_some()
                    && input.channel_id.is_some()
                    && input.partition_bucket.is_some()
            }
            _ => false,
        };
        if !valid_shape {
            bail!("retention reason provenance shape does not match its source kind");
        }
        let statement = Statement::new(
            "INSERT INTO cache_root_reasons
             (id, cache_id, registry_id, store_hash, reason_key, source_kind,
              refresh_id, retention_subscription_id, release_id,
              channel_id, partition_bucket, source_ref,
              source_revision, expires_at, refreshed_at)
             SELECT ?2, refresh.cache_id, refresh.registry_id, ?3, ?4, ?5,
                    refresh.refresh_id, refresh.subscription_id, ?6,
                    ?8, ?9, ?10, refresh.registry_source_revision, ?11, ?12
             FROM cache_retention_refreshes refresh
             WHERE refresh.refresh_id = ?1 AND refresh.state = 'building'
               AND ((?5 = 'registry_catalog'
                     AND ?6 IS NULL AND ?7 IS NULL AND ?8 IS NULL AND ?9 IS NULL
                     AND EXISTS (SELECT 1 FROM registry_catalog_artifacts artifact
                       WHERE artifact.registry_id = refresh.registry_id
                         AND artifact.source_revision = refresh.registry_source_revision
                         AND artifact.store_hash = ?3))
                 OR (?5 = 'release' AND ?6 IS NOT NULL AND ?7 IS NOT NULL
                     AND ?8 IS NULL AND ?9 IS NULL
                     AND EXISTS (SELECT 1 FROM release_artifacts artifact
                       WHERE artifact.snapshot_id = ?7 AND artifact.release_id = ?6
                         AND artifact.registry_id = refresh.registry_id
                         AND artifact.store_hash = ?3))
                 OR (?5 = 'channel' AND ?6 IS NOT NULL AND ?7 IS NOT NULL
                     AND ?8 IS NOT NULL AND ?9 IS NOT NULL
                     AND EXISTS (SELECT 1 FROM channels channel
                       JOIN channel_partitions partition
                         ON partition.channel_id = channel.id AND partition.bucket = ?9
                       JOIN releases release ON release.registry_id = channel.registry_id
                         AND release.semver = partition.release AND release.id = ?6
                       JOIN release_artifacts artifact ON artifact.snapshot_id = ?7
                         AND artifact.release_id = release.id
                         AND artifact.registry_id = release.registry_id
                         AND artifact.store_hash = ?3
                       WHERE channel.id = ?8
                         AND channel.registry_id = refresh.registry_id)))",
            vals![
                refresh_id,
                input.reason_id,
                input.store_hash,
                input.reason_key,
                input.source_kind,
                input.release_id,
                input.release_snapshot_id,
                input.channel_id,
                input.partition_bucket,
                input.source_ref,
                input.expires_at,
                input.refreshed_at
            ],
        )
        .expecting(1);
        let mut statements = vec![statement];
        if let (Some(release_id), Some(snapshot_id)) =
            (input.release_id, input.release_snapshot_id.as_deref())
        {
            statements.push(
                Statement::new(
                    "INSERT INTO cache_root_release_provenance
                     (root_reason_id, cache_id, registry_id, release_id,
                      release_snapshot_id)
                     SELECT reason.id, reason.cache_id, reason.registry_id,
                            ?2, ?3
                     FROM cache_root_reasons reason
                     WHERE reason.id = ?1 AND reason.release_id = ?2
                       AND reason.registry_id IS NOT NULL",
                    vals![input.reason_id, release_id, snapshot_id],
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await
    }

    /// Publishes a complete refresh and advances its subscription and cache epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when reason counts/provenance do not match, any captured
    /// source or version changed, the parent pointer is stale, or persistence
    /// fails.
    pub async fn complete_retention_refresh_topology(
        &self,
        refresh_id: &str,
        mutation_id: &str,
        activated_at: i64,
    ) -> Result<()> {
        validate_stable_key(refresh_id, "retention refresh id")?;
        validate_stable_key(mutation_id, "retention refresh mutation id")?;
        let refresh = self
            .backend
            .query_opt(
                "SELECT cache_id, expected_cache_epoch,
                   expected_parent_refresh_id, subscription_id
                 FROM cache_retention_refreshes
                 WHERE refresh_id = ?1 AND state = 'building'",
                &vals![refresh_id],
            )
            .await?
            .context("retention refresh is missing or not building")?;
        let cache_id: i64 = refresh.get(0)?;
        let expected_epoch: i64 = refresh.get(1)?;
        let expected_parent_refresh_id: Option<String> = refresh.get(2)?;
        let subscription_id: i64 = refresh.get(3)?;
        let mut statements = vec![
            Statement::new(
                "UPDATE cache_retention_refreshes
                 SET state = 'complete', actual_reason_count = (
                       SELECT COUNT(*) FROM cache_root_reasons
                       WHERE refresh_id = ?1),
                     activated_at = ?2,
                     parent_grace_until = ?2 + (SELECT removal_grace_secs
                       FROM cache_retention_subscriptions
                       WHERE id = subscription_id),
                     finished_at = ?2
                 WHERE refresh_id = ?1 AND state = 'building'
                   AND expected_reason_count = (SELECT COUNT(*)
                     FROM cache_root_reasons WHERE refresh_id = ?1)
                   AND EXISTS (SELECT 1 FROM cache_retention_subscriptions sub
                     LEFT JOIN cache_retention_refresh_heads head
                       ON head.subscription_id = sub.id
                     JOIN registry_index idx ON idx.registry_id = sub.registry_id
                     WHERE sub.id = subscription_id
                       AND sub.cache_id = cache_id AND sub.registry_id = registry_id
                       AND sub.resource_version = expected_subscription_version
                       AND sub.selector_digest = selector_digest
                       AND idx.last_indexed_commit = registry_source_revision
                       AND idx.generation = registry_index_generation
                       AND idx.content_digest = registry_index_digest
                       AND sub.enabled = 1 AND sub.retired_at IS NULL
                       AND (head.current_refresh_id = expected_parent_refresh_id
                         OR (head.current_refresh_id IS NULL
                           AND expected_parent_refresh_id IS NULL)))",
                vals![refresh_id, activated_at],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_retention_subscriptions
                 SET last_successful_revision = (SELECT registry_source_revision
                       FROM cache_retention_refreshes WHERE refresh_id = ?1),
                     last_refresh_at = ?2, refresh_state = 'fresh',
                     refresh_error = NULL, resource_version = resource_version + 1,
                     updated_at = ?2
                 WHERE id = (SELECT subscription_id
                   FROM cache_retention_refreshes WHERE refresh_id = ?1)
                   AND resource_version = (SELECT expected_subscription_version
                     FROM cache_retention_refreshes WHERE refresh_id = ?1)
                   AND EXISTS (SELECT 1 FROM cache_retention_refreshes
                     WHERE refresh_id = ?1 AND state = 'complete')",
                vals![refresh_id, activated_at],
            )
            .expecting(1),
        ];
        let head_statement = if expected_parent_refresh_id.is_some() {
            Statement::new(
                "UPDATE cache_retention_refresh_heads
                 SET current_refresh_id = ?1,
                     resource_version = resource_version + 1,
                     updated_at = ?3
                 WHERE subscription_id = ?2
                   AND current_refresh_id = (SELECT expected_parent_refresh_id
                     FROM cache_retention_refreshes WHERE refresh_id = ?1)",
                vals![refresh_id, subscription_id, activated_at],
            )
            .expecting(1)
        } else {
            Statement::new(
                "INSERT INTO cache_retention_refresh_heads
                 (subscription_id, cache_id, registry_id, current_refresh_id,
                  resource_version, updated_at)
                 SELECT subscription_id, cache_id, registry_id, refresh_id, 1, ?2
                 FROM cache_retention_refreshes
                 WHERE refresh_id = ?1 AND state = 'complete'
                   AND expected_parent_refresh_id IS NULL",
                vals![refresh_id, activated_at],
            )
            .expecting(1)
        };
        statements.push(head_statement);
        statements.extend([
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "root_generation = root_generation + 1",
            ),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "root",
                activated_at,
                &format!(
                    "EXISTS (SELECT 1 FROM cache_retention_refreshes refresh JOIN cache_retention_refresh_heads head ON head.current_refresh_id = refresh.refresh_id WHERE refresh.refresh_id = '{}' AND refresh.state = 'complete')",
                    sql_literal(refresh_id)
                ),
            ),
        ]);
        self.backend.checked_batch(&statements).await
    }

    /// Records an unreachable refresh failure without replacing active reasons.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty error, a terminal refresh, or database
    /// failure.
    pub async fn fail_retention_refresh_topology(
        &self,
        refresh_id: &str,
        error: &str,
        finished_at: i64,
    ) -> Result<()> {
        validate_stable_key(refresh_id, "retention refresh id")?;
        if error.trim().is_empty() {
            bail!("retention refresh failure requires an error");
        }
        let statements = vec![
            Statement::new(
                "UPDATE cache_retention_refreshes SET state = 'failed',
                   actual_reason_count = (SELECT COUNT(*) FROM cache_root_reasons
                     WHERE refresh_id = ?1), error = ?2, finished_at = ?3
                 WHERE refresh_id = ?1 AND state = 'building'",
                vals![refresh_id, error, finished_at],
            )
            .expecting(1),
            Statement::new(
                "UPDATE cache_retention_subscriptions
                 SET refresh_state = 'failed', refresh_error = ?2,
                     last_refresh_at = ?3, updated_at = ?3
                 WHERE id = (SELECT subscription_id
                   FROM cache_retention_refreshes WHERE refresh_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM cache_retention_refreshes newer
                     WHERE newer.subscription_id = cache_retention_subscriptions.id
                       AND newer.started_at > (SELECT started_at
                         FROM cache_retention_refreshes WHERE refresh_id = ?1))",
                vals![refresh_id, error, finished_at],
            )
            .unchecked(),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Creates an indefinite or lease-governed root and advances the root epoch.
    ///
    /// The root, optional first lease, active reason, and cache-state CAS are a
    /// single checked atomic batch. A stale epoch cannot leave any of them
    /// behind.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, duplicate identities, a stale cache
    /// epoch, missing cache state, or database failure.
    pub async fn create_manual_retention_root_topology(
        &self,
        input: &CreateManualRetentionRoot,
    ) -> Result<ManualRetentionRootRecord> {
        validate_stable_key(&input.root_id, "manual retention root id")?;
        validate_stable_key(&input.reason_id, "manual retention reason id")?;
        validate_stable_key(&input.mutation_id, "root mutation id")?;
        validate_store_hash(&input.store_hash)?;
        if input.reason.trim().is_empty()
            || input.actor.trim().is_empty()
            || !matches!(input.actor_kind.as_str(), "user" | "service_account")
            || input.actor_id <= 0
        {
            bail!("manual retention root requires a reason and actor");
        }
        if input.expected_epoch < 0 {
            bail!("expected cache epoch cannot be negative");
        }
        if input.lease_id.is_some() != input.lease_expires_at.is_some() {
            bail!("lease id and expiry must be supplied together");
        }
        if let Some(lease_id) = input.lease_id.as_deref() {
            validate_stable_key(lease_id, "retention lease id")?;
        }
        if input
            .lease_expires_at
            .is_some_and(|expires_at| expires_at <= input.now)
        {
            bail!("retention lease expiry must be later than its start");
        }

        let resulting_epoch = input.expected_epoch + 1;
        let protection_kind = if input.lease_id.is_some() {
            "leased"
        } else {
            "indefinite"
        };
        let source_kind = if input.lease_id.is_some() {
            "lease"
        } else {
            "manual"
        };
        let mut statements = vec![epoch_update_statement(
            input.cache_id,
            input.expected_epoch,
            &input.mutation_id,
            "root_generation = root_generation + 1",
        )];
        statements.push(
            Statement::new(
                "INSERT INTO manual_retention_roots
             (id, cache_id, store_hash, protection_kind,
              reason, owner_kind, owner_id, created_by, created_at, resource_version)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1
             WHERE EXISTS (SELECT 1 FROM cache_gc_state
               WHERE cache_id = ?2 AND epoch = ?10 AND epoch_owner_token = ?11)",
                vals![
                    input.root_id,
                    input.cache_id,
                    input.store_hash,
                    protection_kind,
                    input.reason,
                    input.actor_kind,
                    input.actor_id,
                    input.actor,
                    input.now,
                    resulting_epoch,
                    input.mutation_id
                ],
            )
            .expecting(1),
        );
        if let (Some(lease_id), Some(expires_at)) =
            (input.lease_id.as_deref(), input.lease_expires_at)
        {
            statements.push(
                Statement::new(
                    "INSERT INTO retention_leases
                 (id, manual_retention_root_id, begins_at, expires_at,
                  renewed_from_lease_id, state, renewed_by, renewed_at,
                  resource_version)
                 SELECT ?1, ?2, ?3, ?4, NULL, 'active', ?5, ?3, 1
                 WHERE EXISTS (SELECT 1 FROM manual_retention_roots
                   WHERE id = ?2 AND cache_id = ?6 AND deleted_at IS NULL)",
                    vals![
                        lease_id,
                        input.root_id,
                        input.now,
                        expires_at,
                        input.actor,
                        input.cache_id
                    ],
                )
                .expecting(1),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO manual_retention_lease_heads
                     (manual_retention_root_id, cache_id, current_lease_id,
                      resource_version, updated_at)
                     SELECT ?1, ?3, ?2, 1, ?4
                     WHERE EXISTS (SELECT 1 FROM retention_leases
                       WHERE id = ?2 AND manual_retention_root_id = ?1
                         AND state = 'active')",
                    vals![input.root_id, lease_id, input.cache_id, input.now],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "INSERT INTO cache_root_reasons
             (id, cache_id, registry_id, store_hash, reason_key, source_kind,
              refresh_id, retention_subscription_id, manual_retention_root_id,
              retention_lease_id, release_id, channel_id,
              partition_bucket, source_ref, source_revision, expires_at,
              refreshed_at)
             SELECT ?1, ?2, NULL, ?3, ?4, ?5, NULL, NULL, ?6, ?7,
                    NULL, NULL, NULL, ?8, '1', ?9, ?10
             WHERE EXISTS (SELECT 1 FROM manual_retention_roots root
               LEFT JOIN manual_retention_lease_heads head
                 ON head.manual_retention_root_id = root.id
               WHERE root.id = ?6 AND root.cache_id = ?2
                 AND root.deleted_at IS NULL
                 AND ((?5 = 'manual' AND root.protection_kind = 'indefinite')
                   OR (?5 = 'lease' AND head.current_lease_id = ?7)))",
                vals![
                    input.reason_id,
                    input.cache_id,
                    input.store_hash,
                    input.root_id,
                    source_kind,
                    input.root_id,
                    input.lease_id,
                    input.root_id,
                    input.lease_expires_at,
                    input.now
                ],
            )
            .expecting(1),
        );
        statements.push(epoch_assertion_statement(
            &input.mutation_id,
            input.cache_id,
            input.expected_epoch,
            "root",
            input.now,
            &format!(
                "EXISTS (SELECT 1 FROM manual_retention_roots WHERE id = '{}' AND cache_id = {}) AND EXISTS (SELECT 1 FROM cache_root_reasons WHERE id = '{}')",
                sql_literal(&input.root_id),
                input.cache_id,
                sql_literal(&input.reason_id)
            ),
        ));
        self.backend.checked_batch(&statements).await?;
        self.manual_retention_root(input.cache_id, &input.root_id)
            .await?
            .context("created manual retention root disappeared")
    }

    /// Renews the exact current lease by appending an immutable successor.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a stale root/epoch, a missing active
    /// lease head, duplicate identities, or database failure.
    pub async fn renew_retention_lease_topology(
        &self,
        input: &RenewRetentionLease,
    ) -> Result<RetentionLeaseRecord> {
        validate_stable_key(&input.root_id, "manual retention root id")?;
        validate_stable_key(&input.lease_id, "retention lease id")?;
        validate_stable_key(&input.reason_id, "retention reason id")?;
        validate_stable_key(&input.mutation_id, "lease mutation id")?;
        if input.expected_root_version <= 0 || input.expected_epoch < 0 {
            bail!("expected root version must be positive and epoch non-negative");
        }
        if input.expires_at <= input.now || input.actor.trim().is_empty() {
            bail!("lease renewal requires an actor and a future expiry");
        }
        let resulting_epoch = input.expected_epoch + 1;
        let statements = vec![
            epoch_update_statement(
                input.cache_id,
                input.expected_epoch,
                &input.mutation_id,
                "root_generation = root_generation + 1",
            ),
            Statement::new(
                "INSERT INTO retention_leases
                 (id, manual_retention_root_id, begins_at, expires_at,
                  renewed_from_lease_id, state, renewed_by, renewed_at,
                  resource_version)
                 SELECT ?1, root.id, ?2, ?3, head.current_lease_id,
                        'active', ?4, ?2, 1
                 FROM manual_retention_roots root
                 JOIN manual_retention_lease_heads head
                   ON head.manual_retention_root_id = root.id
                  AND head.cache_id = root.cache_id
                 JOIN retention_leases prior ON prior.id = head.current_lease_id
                 WHERE root.id = ?5 AND root.cache_id = ?6
                   AND root.resource_version = ?7 AND root.deleted_at IS NULL
                   AND root.protection_kind = 'leased' AND prior.state = 'active'
                   AND EXISTS (SELECT 1 FROM cache_gc_state WHERE cache_id = ?6
                     AND epoch = ?8 AND epoch_owner_token = ?9)",
                vals![
                    input.lease_id,
                    input.now,
                    input.expires_at,
                    input.actor,
                    input.root_id,
                    input.cache_id,
                    input.expected_root_version,
                    resulting_epoch,
                    input.mutation_id
                ],
            ).expecting(1),
            Statement::new(
                "UPDATE retention_leases SET state = 'superseded',
                   resource_version = resource_version + 1
                 WHERE id = (SELECT renewed_from_lease_id FROM retention_leases
                   WHERE id = ?1 AND manual_retention_root_id = ?2)
                   AND manual_retention_root_id = ?2 AND state = 'active'",
                vals![input.lease_id, input.root_id],
            ).expecting(1),
            Statement::new(
                "UPDATE manual_retention_roots
                 SET resource_version = resource_version + 1
                 WHERE id = ?2 AND cache_id = ?3 AND resource_version = ?4
                   AND EXISTS (SELECT 1 FROM retention_leases WHERE id = ?1
                     AND manual_retention_root_id = ?2 AND state = 'active')",
                vals![
                    input.lease_id,
                    input.root_id,
                    input.cache_id,
                    input.expected_root_version
                ],
            ).expecting(1),
            Statement::new(
                "UPDATE manual_retention_lease_heads
                 SET current_lease_id = ?1,
                     resource_version = resource_version + 1,
                     updated_at = ?5
                 WHERE manual_retention_root_id = ?2 AND cache_id = ?3
                   AND current_lease_id = (SELECT renewed_from_lease_id
                     FROM retention_leases WHERE id = ?1)
                   AND EXISTS (SELECT 1 FROM manual_retention_roots
                     WHERE id = ?2 AND cache_id = ?3 AND resource_version = ?4 + 1)",
                vals![
                    input.lease_id,
                    input.root_id,
                    input.cache_id,
                    input.expected_root_version,
                    input.now
                ],
            ).expecting(1),
            Statement::new(
                "INSERT INTO cache_root_reasons
                 (id, cache_id, store_hash, reason_key, source_kind,
                  manual_retention_root_id, retention_lease_id, source_ref,
                  source_revision, expires_at, refreshed_at)
                 SELECT ?1, root.cache_id, root.store_hash, ?2, 'lease',
                        root.id, ?2, root.id,
                        ?7, ?4, ?5
                 FROM manual_retention_roots root
                 JOIN manual_retention_lease_heads head
                   ON head.manual_retention_root_id = root.id
                 WHERE root.id = ?3 AND root.cache_id = ?6
                   AND head.current_lease_id = ?2 AND root.deleted_at IS NULL",
                vals![
                    input.reason_id,
                    input.lease_id,
                    input.root_id,
                    input.expires_at,
                    input.now,
                    input.cache_id,
                    (input.expected_root_version + 1).to_string()
                ],
            ).expecting(1),
            epoch_assertion_statement(
                &input.mutation_id,
                input.cache_id,
                input.expected_epoch,
                "root",
                input.now,
                &format!(
                    "EXISTS (SELECT 1 FROM manual_retention_lease_heads WHERE manual_retention_root_id = '{}' AND cache_id = {} AND current_lease_id = '{}') AND EXISTS (SELECT 1 FROM cache_root_reasons WHERE id = '{}')",
                    sql_literal(&input.root_id),
                    input.cache_id,
                    sql_literal(&input.lease_id),
                    sql_literal(&input.reason_id)
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await?;
        self.retention_lease(&input.lease_id)
            .await?
            .context("renewed retention lease disappeared")
    }

    /// Revokes only the exact current lease head and advances the root epoch.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a historical/non-current lease, a
    /// stale root/epoch, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_retention_lease_topology(
        &self,
        cache_id: i64,
        lease_id: &str,
        expected_root_version: i64,
        expected_epoch: i64,
        mutation_id: &str,
        actor: &str,
        now: i64,
    ) -> Result<RetentionLeaseRecord> {
        validate_stable_key(lease_id, "retention lease id")?;
        validate_stable_key(mutation_id, "lease mutation id")?;
        if expected_root_version <= 0 || expected_epoch < 0 || actor.trim().is_empty() {
            bail!("lease revocation requires valid expected versions and actor");
        }
        let statements = vec![
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "root_generation = root_generation + 1",
            ),
            Statement::new(
                "UPDATE retention_leases SET state = 'revoked', revoked_by = ?2,
                   revoked_at = ?3, resource_version = resource_version + 1
                 WHERE id = ?1 AND state = 'active'
                   AND EXISTS (SELECT 1 FROM manual_retention_roots root
                     JOIN manual_retention_lease_heads head
                       ON head.manual_retention_root_id = root.id
                     WHERE root.id = manual_retention_root_id
                       AND root.cache_id = ?4 AND head.current_lease_id = ?1
                       AND root.resource_version = ?5 AND root.deleted_at IS NULL)",
                vals![lease_id, actor, now, cache_id, expected_root_version],
            ).expecting(1),
            Statement::new(
                "UPDATE manual_retention_roots
                 SET resource_version = resource_version + 1
                 WHERE cache_id = ?1 AND resource_version = ?3
                   AND EXISTS (SELECT 1 FROM manual_retention_lease_heads head
                     WHERE head.manual_retention_root_id = manual_retention_roots.id
                       AND head.current_lease_id = ?2)
                   AND EXISTS (SELECT 1 FROM retention_leases
                     WHERE id = ?2 AND state = 'revoked')",
                vals![cache_id, lease_id, expected_root_version],
            ).expecting(1),
            Statement::new(
                "DELETE FROM manual_retention_lease_heads
                 WHERE cache_id = ?1 AND current_lease_id = ?2
                   AND EXISTS (SELECT 1 FROM retention_leases
                     WHERE id = ?2 AND state = 'revoked')",
                vals![cache_id, lease_id],
            ).expecting(1),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "root",
                now,
                &format!(
                    "EXISTS (SELECT 1 FROM retention_leases lease JOIN manual_retention_roots root ON root.id = lease.manual_retention_root_id WHERE lease.id = '{}' AND lease.state = 'revoked' AND root.cache_id = {} AND NOT EXISTS (SELECT 1 FROM manual_retention_lease_heads head WHERE head.manual_retention_root_id = root.id))",
                    sql_literal(lease_id),
                    cache_id
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await?;
        self.retention_lease(lease_id)
            .await?
            .context("revoked retention lease disappeared")
    }

    /// Logically deletes a manual root and clears its exact active protection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a stale root/epoch, or database
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_manual_retention_root_topology(
        &self,
        cache_id: i64,
        root_id: &str,
        expected_root_version: i64,
        expected_epoch: i64,
        mutation_id: &str,
        actor: &str,
        now: i64,
    ) -> Result<()> {
        validate_stable_key(root_id, "manual retention root id")?;
        validate_stable_key(mutation_id, "root mutation id")?;
        if expected_root_version <= 0 || expected_epoch < 0 || actor.trim().is_empty() {
            bail!("root deletion requires valid expected versions and actor");
        }
        let statements = vec![
            epoch_update_statement(
                cache_id,
                expected_epoch,
                mutation_id,
                "root_generation = root_generation + 1",
            ),
            Statement::new(
                 "UPDATE retention_leases SET state = 'revoked', revoked_by = ?4,
                   revoked_at = ?5, resource_version = resource_version + 1
                 WHERE id = (SELECT head.current_lease_id
                   FROM manual_retention_roots root
                   JOIN manual_retention_lease_heads head
                     ON head.manual_retention_root_id = root.id
                   WHERE root.id = ?1 AND root.cache_id = ?2
                     AND root.resource_version = ?3 AND root.deleted_at IS NULL)
                   AND state = 'active'",
                vals![root_id, cache_id, expected_root_version, actor, now],
            ).unchecked(),
            Statement::new(
                "DELETE FROM manual_retention_lease_heads
                 WHERE manual_retention_root_id = ?1 AND cache_id = ?2",
                vals![root_id, cache_id],
            ).unchecked(),
            Statement::new(
                "UPDATE manual_retention_roots SET deleted_at = ?4,
                   resource_version = resource_version + 1
                 WHERE id = ?1 AND cache_id = ?2 AND resource_version = ?3
                   AND deleted_at IS NULL",
                vals![root_id, cache_id, expected_root_version, now],
            ).expecting(1),
            epoch_assertion_statement(
                mutation_id,
                cache_id,
                expected_epoch,
                "root",
                now,
                &format!(
                    "EXISTS (SELECT 1 FROM manual_retention_roots WHERE id = '{}' AND cache_id = {} AND deleted_at = {} AND NOT EXISTS (SELECT 1 FROM manual_retention_lease_heads head WHERE head.manual_retention_root_id = manual_retention_roots.id))",
                    sql_literal(root_id),
                    cache_id,
                    now
                ),
            ),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Returns the cache-wide GC concurrency state.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_gc_topology_state(
        &self,
        cache_id: i64,
    ) -> Result<Option<CacheGcStateRecord>> {
        self.backend
            .query_opt(
                "SELECT state.cache_id, state.epoch, state.epoch_owner_token,
                 state.root_generation, state.object_graph_generation,
                 state.inventory_generation, state.topology_generation,
                 head.current_mark_generation_id, state.destructive_enabled,
                 state.resource_version
                 FROM cache_gc_state state
                 JOIN cache_gc_heads head ON head.cache_id = state.cache_id
                 WHERE state.cache_id = ?1",
                &vals![cache_id],
            )
            .await?
            .map(|row| row_to_cache_gc_state(&row))
            .transpose()
    }

    /// Returns one active logical cache object from the normalized graph.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn normalized_cache_object(
        &self,
        cache_id: i64,
        store_hash: &str,
    ) -> Result<Option<CacheObjectRecord>> {
        let row = self
            .backend
            .query_opt(
                &format!(
                    "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                     FROM cache_objects object
                     JOIN surface_objects nar
                       ON nar.id = object.nar_surface_object_id
                      AND nar.cache_id = object.cache_id
                     WHERE object.cache_id = ?1 AND object.store_hash = ?2
                       AND object.lifecycle_state = 'active'"
                ),
                &vals![cache_id, store_hash],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(self.cache_object_record_from_row(&row).await?)),
            None => Ok(None),
        }
    }

    /// Returns one tombstoned logical cache object eligible for exact reactivation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn tombstoned_cache_object(
        &self,
        cache_id: i64,
        store_hash: &str,
    ) -> Result<Option<CacheObjectRecord>> {
        let row = self
            .backend
            .query_opt(
                &format!(
                    "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                     FROM cache_objects object
                     JOIN surface_objects nar
                       ON nar.id = object.nar_surface_object_id
                      AND nar.cache_id = object.cache_id
                     WHERE object.cache_id = ?1 AND object.store_hash = ?2
                       AND object.lifecycle_state = 'tombstoned'"
                ),
                &vals![cache_id, store_hash],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(self.cache_object_record_from_row(&row).await?)),
            None => Ok(None),
        }
    }

    /// Lists active logical cache objects from the normalized graph.
    ///
    /// A negative limit requests the complete active inventory.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_normalized_cache_objects(
        &self,
        cache_id: i64,
        limit: i64,
    ) -> Result<Vec<CacheObjectRecord>> {
        let sql = if limit < 0 {
            format!(
                "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                 FROM cache_objects object
                 JOIN surface_objects nar
                   ON nar.id = object.nar_surface_object_id
                  AND nar.cache_id = object.cache_id
                 WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                 ORDER BY object.store_name, object.id"
            )
        } else {
            format!(
                "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                 FROM cache_objects object
                 JOIN surface_objects nar
                   ON nar.id = object.nar_surface_object_id
                  AND nar.cache_id = object.cache_id
                 WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                 ORDER BY object.store_name, object.id LIMIT ?2"
            )
        };
        let rows = if limit < 0 {
            self.backend.query(&sql, &vals![cache_id]).await?
        } else {
            self.backend.query(&sql, &vals![cache_id, limit]).await?
        };
        let mut objects = Vec::with_capacity(rows.len());
        for row in &rows {
            objects.push(self.cache_object_record_from_row(row).await?);
        }
        Ok(objects)
    }

    /// Lists every logical surface object owned by a binary cache.
    ///
    /// This includes tombstoned objects and objects shared by more than one
    /// logical narinfo, so an inventory publication never drops their physical
    /// presence merely because they are absent from the active browse graph.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_cache_surface_objects(
        &self,
        cache_id: i64,
    ) -> Result<Vec<SurfaceObjectRecord>> {
        self.backend
            .query(
                &format!(
                    "SELECT {} FROM surface_objects
                     WHERE cache_id = ?1 ORDER BY id",
                    super::SURFACE_OBJECT_COLUMNS
                ),
                &vals![cache_id],
            )
            .await?
            .iter()
            .map(super::row_to_surface_object)
            .collect()
    }

    /// Records a debounced serving-path access observation for a cache object.
    ///
    /// Access recency is advisory input to future eviction ordering; retention
    /// roots remain the correctness boundary. Missing objects and observations
    /// inside the debounce window are intentional no-ops.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative timestamp or database failure.
    pub async fn touch_cache_object(
        &self,
        cache_id: i64,
        store_hash: &str,
        observed_at: i64,
    ) -> Result<()> {
        if observed_at < 0 {
            bail!("cache access observation time cannot be negative");
        }
        let stale_before = observed_at.saturating_sub(ACCESS_OBSERVATION_DEBOUNCE_SECS);
        self.backend
            .execute(
                "UPDATE cache_objects
                 SET last_access_observed_at = ?3, last_access_source = 'serving_read'
                 WHERE cache_id = ?1 AND store_hash = ?2
                   AND lifecycle_state = 'active'
                   AND (last_access_observed_at IS NULL OR last_access_observed_at < ?4)",
                &vals![cache_id, store_hash, observed_at, stale_before],
            )
            .await?;
        Ok(())
    }

    /// Returns aggregate logical usage for one binary cache.
    ///
    /// The normalized object graph is authoritative, so this value is derived
    /// directly instead of being maintained as a second mutable counter.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_usage(&self, cache_id: i64) -> Result<CacheUsage> {
        let row = self
            .backend
            .query_opt(
                "SELECT COALESCE(SUM(file_size), 0), COUNT(*),
                        COALESCE(MAX(published_at), 0)
                 FROM cache_objects
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'",
                &vals![cache_id],
            )
            .await?
            .context("cache usage aggregate returned no row")?;
        Ok(CacheUsage {
            used_bytes: row.get(0)?,
            object_count: row.get(1)?,
            updated_at: row.get(2)?,
        })
    }

    /// Returns instance-wide cache and garbage-collection metrics.
    ///
    /// Live-cache filtering matches the serving inventory: a cache is excluded
    /// after either the cache itself or its owning organization is soft-deleted.
    /// GC counters come from final topology operations and confirmed physical
    /// deletion jobs rather than the removed pre-cutover run ledger.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_metrics(&self) -> Result<CacheMetrics> {
        const LIVE_CACHE: &str = "cache.deleted_at IS NULL AND \
             (cache.org_id IS NULL OR NOT EXISTS (SELECT 1 FROM orgs org \
              WHERE org.id = cache.org_id AND org.deleted_at IS NOT NULL))";

        let cache_count = self
            .backend
            .query_opt(
                &format!("SELECT COUNT(*) FROM binary_caches cache WHERE {LIVE_CACHE}"),
                &[],
            )
            .await?
            .context("cache metric aggregate returned no row")?
            .get(0)?;
        let usage = self
            .backend
            .query_opt(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(object.file_size), 0) \
                     FROM cache_objects object \
                     JOIN binary_caches cache ON cache.id = object.cache_id \
                     WHERE object.lifecycle_state = 'active' AND {LIVE_CACHE}"
                ),
                &[],
            )
            .await?
            .context("cache object metric aggregate returned no row")?;
        let operations = self
            .backend
            .query_opt(
                "SELECT COALESCE(SUM(CASE WHEN state = 'succeeded' THEN 1 ELSE 0 END), 0), \
                        COALESCE(SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END), 0) \
                 FROM topology_operations WHERE operation_kind = 'cache_gc'",
                &[],
            )
            .await?
            .context("cache GC operation metric aggregate returned no row")?;
        let reclaimed = self
            .backend
            .query_opt(
                "SELECT COALESCE(SUM(confirmed_reclaimed_bytes), 0) \
                 FROM object_deletion_jobs WHERE state = 'succeeded'",
                &[],
            )
            .await?
            .context("cache GC reclaimed-byte aggregate returned no row")?
            .get(0)?;

        Ok(CacheMetrics {
            cache_count,
            object_count: usage.get(0)?,
            used_bytes: usage.get(1)?,
            gc_runs_ok: operations.get(0)?,
            gc_runs_failed: operations.get(1)?,
            gc_freed_bytes: reclaimed,
        })
    }

    /// Searches active logical cache objects by name, hash, or deriver.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn search_normalized_cache_objects(
        &self,
        cache_id: i64,
        query: &str,
        limit: i64,
    ) -> Result<Vec<CacheObjectRecord>> {
        let like = format!("%{query}%");
        let sql = if limit < 0 {
            format!(
                "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                     FROM cache_objects object
                     JOIN surface_objects nar
                       ON nar.id = object.nar_surface_object_id
                      AND nar.cache_id = object.cache_id
                     WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                       AND (object.store_name LIKE ?2 OR object.store_hash LIKE ?2
                         OR object.deriver LIKE ?2)
                     ORDER BY object.store_name, object.id"
            )
        } else {
            format!(
                "SELECT {CACHE_OBJECT_RECORD_COLUMNS}
                     FROM cache_objects object
                     JOIN surface_objects nar
                       ON nar.id = object.nar_surface_object_id
                      AND nar.cache_id = object.cache_id
                     WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                       AND (object.store_name LIKE ?2 OR object.store_hash LIKE ?2
                         OR object.deriver LIKE ?2)
                     ORDER BY object.store_name, object.id LIMIT ?3"
            )
        };
        let rows = if limit < 0 {
            self.backend.query(&sql, &vals![cache_id, like]).await?
        } else {
            self.backend
                .query(&sql, &vals![cache_id, like, limit])
                .await?
        };
        let mut objects = Vec::with_capacity(rows.len());
        for row in &rows {
            objects.push(self.cache_object_record_from_row(row).await?);
        }
        Ok(objects)
    }

    async fn cache_object_record_from_row(&self, row: &Row) -> Result<CacheObjectRecord> {
        let cache_id: i64 = row.get(1)?;
        let object_id: i64 = row.get(0)?;
        let reference_rows = self
            .backend
            .query(
                "SELECT referenced_store_hash FROM cache_object_references
                 WHERE cache_id = ?1 AND cache_object_id = ?2
                 ORDER BY referenced_store_hash",
                &vals![cache_id, object_id],
            )
            .await?;
        let references = reference_rows
            .iter()
            .map(|reference| reference.get(0))
            .collect::<Result<Vec<String>>>()?;
        Ok(CacheObjectRecord {
            id: object_id,
            cache_id,
            store_hash: row.get(2)?,
            store_name: row.get(3)?,
            narinfo_surface_object_id: row.get(4)?,
            nar_surface_object_id: row.get(5)?,
            nar_url: row.get(6)?,
            nar_hash: row.get(7)?,
            nar_size: row.get(8)?,
            file_hash: row.get(9)?,
            file_size: row.get(10)?,
            compression: row.get(11)?,
            deriver: row.get(12)?,
            references,
            signature: row.get(13)?,
            content_address: row.get(14)?,
            published_at: row.get(15)?,
            last_access_observed_at: row.get(16)?,
            resource_version: row.get(17)?,
        })
    }

    /// Returns one stable manual retention root.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn manual_retention_root(
        &self,
        cache_id: i64,
        root_id: &str,
    ) -> Result<Option<ManualRetentionRootRecord>> {
        self.backend
            .query_opt(
                "SELECT root.id, root.cache_id, root.store_hash,
                 root.protection_kind, head.current_lease_id, root.reason,
                 root.owner_kind, root.owner_id, root.created_by, root.created_at,
                 root.deleted_at, root.resource_version FROM manual_retention_roots root
                 LEFT JOIN manual_retention_lease_heads head
                   ON head.manual_retention_root_id = root.id
                 WHERE root.cache_id = ?1 AND root.id = ?2",
                &vals![cache_id, root_id],
            )
            .await?
            .map(|row| row_to_manual_retention_root(&row))
            .transpose()
    }

    /// Returns one immutable lease-history row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn retention_lease(&self, lease_id: &str) -> Result<Option<RetentionLeaseRecord>> {
        self.backend
            .query_opt(
                "SELECT id, manual_retention_root_id, begins_at, expires_at,
                 renewed_from_lease_id, state, renewed_by, renewed_at,
                 revoked_by, revoked_at, resource_version
                 FROM retention_leases WHERE id = ?1",
                &vals![lease_id],
            )
            .await?
            .map(|row| row_to_retention_lease(&row))
            .transpose()
    }

    /// Lists only reasons active at the supplied GC cutoff.
    ///
    /// Current complete refresh generations are entry points. Parent refreshes
    /// participate only while their child's grace is live. Manual and leased
    /// roots are checked against the current root and lease heads.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn active_cache_root_reasons(
        &self,
        cache_id: i64,
        cutoff_at: i64,
    ) -> Result<Vec<CacheRootReasonRecord>> {
        let rows = self
            .backend
            .query(
                "WITH RECURSIVE active_refreshes(refresh_id, subscription_id) AS (
                   SELECT head.current_refresh_id, sub.id
                   FROM cache_retention_subscriptions sub
                   JOIN cache_retention_refresh_heads head
                     ON head.subscription_id = sub.id
                   WHERE sub.cache_id = ?1
                     AND ((enabled = 1 AND retired_at IS NULL)
                       OR (retired_at IS NOT NULL
                         AND retired_at + removal_grace_secs > ?2))
                   UNION ALL
                   SELECT parent.refresh_id, parent.subscription_id
                   FROM active_refreshes active
                   JOIN cache_retention_refreshes child
                     ON child.refresh_id = active.refresh_id
                   JOIN cache_retention_refreshes parent
                     ON parent.refresh_id = child.parent_refresh_id
                   WHERE child.parent_grace_until > ?2
                     AND parent.state = 'complete'
                 )
                 SELECT r.id, r.cache_id, r.registry_id, r.store_hash,
                   r.reason_key, r.source_kind, r.refresh_id,
                   r.retention_subscription_id, r.manual_retention_root_id,
                   r.retention_lease_id, r.release_id,
                   release_provenance.release_snapshot_id,
                   r.channel_id, r.partition_bucket, r.source_ref,
                   r.source_revision, r.expires_at, r.refreshed_at
                 FROM cache_root_reasons r
                 LEFT JOIN manual_retention_roots root
                   ON root.id = r.manual_retention_root_id
                 LEFT JOIN retention_leases lease
                   ON lease.id = r.retention_lease_id
                 LEFT JOIN manual_retention_lease_heads lease_head
                   ON lease_head.manual_retention_root_id = root.id
                 LEFT JOIN cache_root_release_provenance release_provenance
                   ON release_provenance.root_reason_id = r.id
                 WHERE r.cache_id = ?1
                   AND (r.expires_at IS NULL OR r.expires_at > ?2)
                   AND ((r.refresh_id IS NOT NULL AND EXISTS (
                         SELECT 1 FROM active_refreshes active
                         WHERE active.refresh_id = r.refresh_id))
                     OR (r.source_kind = 'manual' AND root.deleted_at IS NULL
                         AND root.protection_kind = 'indefinite')
                     OR (r.source_kind = 'lease' AND root.deleted_at IS NULL
                         AND root.protection_kind = 'leased'
                         AND lease_head.current_lease_id = lease.id
                         AND lease.state = 'active'
                         AND lease.begins_at <= ?2 AND lease.expires_at > ?2))
                 ORDER BY r.store_hash, r.source_kind, r.reason_key, r.id",
                &vals![cache_id, cutoff_at],
            )
            .await?;
        rows.iter().map(row_to_cache_root_reason).collect()
    }

    /// Returns one placement-scoped deletion job.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn object_deletion_job(
        &self,
        cache_id: i64,
        job_id: &str,
    ) -> Result<Option<ObjectDeletionJobRecord>> {
        self.backend
            .query_opt(
                "SELECT job_id, cache_id, originating_operation_id,
                 surface_object_id, placement_id, phase, state, attempt_count,
                 max_attempts, next_attempt_at, error_class, error,
                 confirmed_reclaimed_bytes, leaked_bytes, resource_version
                 FROM object_deletion_jobs WHERE cache_id = ?1 AND job_id = ?2",
                &vals![cache_id, job_id],
            )
            .await?
            .map(|row| row_to_object_deletion_job(&row))
            .transpose()
    }

    /// Returns one durable physical-deletion attempt receipt.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn object_deletion_attempt_receipt(
        &self,
        request_id: &str,
    ) -> Result<Option<ObjectDeletionAttemptReceipt>> {
        self.backend
            .query_opt(
                "SELECT request_id, cache_id, job_id, attempt_number,
                   placement_id, surface_object_id, object_key, expected_etag,
                   expected_hash, expected_size, expected_inventory_generation,
                   binding_id, binding_resource_version,
                   delete_credential_generation, state, outcome,
                   response_etag, response_hash, response_size,
                   error_class, response_detail, requested_at, responded_at,
                   finalized_at
                 FROM object_deletion_attempt_receipts WHERE request_id = ?1",
                &vals![request_id],
            )
            .await?
            .map(|row| row_to_object_deletion_attempt_receipt(&row))
            .transpose()
    }

    /// Returns the current durable attempt for a running deletion job.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn current_object_deletion_attempt_receipt(
        &self,
        cache_id: i64,
        job_id: &str,
    ) -> Result<Option<ObjectDeletionAttemptReceipt>> {
        self.backend
            .query_opt(
                "SELECT receipt.request_id, receipt.cache_id, receipt.job_id,
                   receipt.attempt_number, receipt.placement_id,
                   receipt.surface_object_id, receipt.object_key,
                   receipt.expected_etag, receipt.expected_hash,
                   receipt.expected_size, receipt.expected_inventory_generation,
                   receipt.binding_id, receipt.binding_resource_version,
                   receipt.delete_credential_generation, receipt.state,
                   receipt.outcome, receipt.response_etag,
                   receipt.response_hash, receipt.response_size,
                   receipt.error_class, receipt.response_detail,
                   receipt.requested_at, receipt.responded_at, receipt.finalized_at
                 FROM object_deletion_attempt_receipts receipt
                 JOIN object_deletion_jobs job ON job.job_id = receipt.job_id
                   AND job.cache_id = receipt.cache_id
                   AND job.attempt_count = receipt.attempt_number
                 WHERE receipt.cache_id = ?1 AND receipt.job_id = ?2
                   AND job.state = 'running'",
                &vals![cache_id, job_id],
            )
            .await?
            .map(|row| row_to_object_deletion_attempt_receipt(&row))
            .transpose()
    }

    /// Lists due or crash-recoverable physical-deletion jobs globally.
    ///
    /// Running jobs sort first so a persisted backend response is finalized
    /// before new capacity is claimed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_runnable_object_deletion_jobs(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<ObjectDeletionJobRecord>> {
        if !(1..=1000).contains(&limit) {
            bail!("physical-deletion job limit must be between 1 and 1000");
        }
        self.backend
            .query(
                "SELECT job_id, cache_id, originating_operation_id,
                   surface_object_id, placement_id, phase, state, attempt_count,
                   max_attempts, next_attempt_at, error_class, error,
                   confirmed_reclaimed_bytes, leaked_bytes, resource_version
                 FROM object_deletion_jobs
                 WHERE active_slot = 1 AND (
                   state = 'running' OR (
                     state IN ('pending', 'failed', 'blocked')
                     AND attempt_count < max_attempts
                     AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)
                     AND NOT EXISTS (SELECT 1 FROM cache_gc_action_jobs link
                       JOIN cache_gc_action_dependencies dependency
                         ON dependency.cache_id = link.cache_id
                        AND dependency.plan_id = link.plan_id
                        AND dependency.action_id = link.action_id
                       JOIN cache_gc_action_jobs prior_link
                         ON prior_link.cache_id = dependency.cache_id
                        AND prior_link.plan_id = dependency.plan_id
                        AND prior_link.action_id = dependency.prerequisite_action_id
                       JOIN object_deletion_jobs prior
                         ON prior.job_id = prior_link.job_id
                        AND prior.cache_id = prior_link.cache_id
                       WHERE link.cache_id = object_deletion_jobs.cache_id
                         AND link.job_id = object_deletion_jobs.job_id
                         AND prior.state <> 'succeeded')))
                 ORDER BY CASE WHEN state = 'running' THEN 0 ELSE 1 END,
                   COALESCE(next_attempt_at, created_at), job_id
                 LIMIT ?2",
                &vals![now, limit],
            )
            .await?
            .iter()
            .map(row_to_object_deletion_job)
            .collect()
    }

    /// Persists one backend response before it may affect job or presence state.
    ///
    /// Exact retries are idempotent. A different response for the same request
    /// identity is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed outcomes, a missing/stale request, a
    /// conflicting replay, or database failure.
    pub async fn record_object_deletion_attempt_response(
        &self,
        input: &RecordObjectDeletionAttemptResponse,
    ) -> Result<ObjectDeletionAttemptReceipt> {
        validate_stable_key(&input.request_id, "cache GC deletion request id")?;
        let success = matches!(input.outcome.as_str(), "deleted" | "not_found");
        let failure = matches!(
            input.outcome.as_str(),
            "precondition_failed" | "backend_error"
        );
        if (!success && !failure)
            || (success && (input.error_class.is_some() || input.response_detail.is_some()))
            || (failure
                && (input.error_class.as_deref().is_none_or(str::is_empty)
                    || input.response_detail.as_deref().is_none_or(str::is_empty)))
            || input.response_size.is_some_and(|size| size < 0)
        {
            bail!("physical-deletion backend response is invalid");
        }
        let current = self
            .object_deletion_attempt_receipt(&input.request_id)
            .await?
            .context("physical-deletion request does not exist")?;
        if current.cache_id != input.cache_id || current.job_id != input.job_id {
            bail!("physical-deletion response target does not match its request");
        }
        if current.state != "requested" {
            if current.outcome.as_deref() == Some(input.outcome.as_str())
                && current.response_etag == input.response_etag
                && current.response_hash == input.response_hash
                && current.response_size == input.response_size
                && current.error_class == input.error_class
                && current.response_detail == input.response_detail
            {
                return Ok(current);
            }
            bail!("physical-deletion request was already answered differently");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE object_deletion_attempt_receipts
                 SET state = 'responded', outcome = ?4, response_etag = ?5,
                     response_hash = ?6, response_size = ?7, error_class = ?8,
                     response_detail = ?9, responded_at = ?10
                 WHERE request_id = ?1 AND cache_id = ?2 AND job_id = ?3
                   AND state = 'requested'",
                vals![
                    input.request_id,
                    input.cache_id,
                    input.job_id,
                    input.outcome,
                    input.response_etag,
                    input.response_hash,
                    input.response_size,
                    input.error_class,
                    input.response_detail,
                    input.responded_at
                ],
            )
            .expecting(1)])
            .await?;
        self.object_deletion_attempt_receipt(&input.request_id)
            .await?
            .context("recorded physical-deletion response disappeared")
    }

    /// Returns one cache-global GC policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_gc_policy_topology(
        &self,
        cache_id: i64,
    ) -> Result<Option<CacheGcPolicyRecord>> {
        self.backend
            .query_opt(
                "SELECT cache_id, unreferenced_grace_secs, soft_max_bytes,
                   soft_max_objects, schedule_secs, deletion_concurrency,
                   retry_initial_secs, retry_max_secs, retry_max_attempts,
                   tombstone_retention_secs, resource_version
                 FROM cache_gc_policies WHERE cache_id = ?1",
                &vals![cache_id],
            )
            .await?
            .map(|row| {
                Ok(CacheGcPolicyRecord {
                    cache_id: row.get(0)?,
                    unreferenced_grace_secs: row.get(1)?,
                    soft_max_bytes: row.get(2)?,
                    soft_max_objects: row.get(3)?,
                    schedule_secs: row.get(4)?,
                    deletion_concurrency: row.get(5)?,
                    retry_initial_secs: row.get(6)?,
                    retry_max_secs: row.get(7)?,
                    retry_max_attempts: row.get(8)?,
                    tombstone_retention_secs: row.get(9)?,
                    resource_version: row.get(10)?,
                })
            })
            .transpose()
    }

    /// Lists manual retention roots, including retained deletion history.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_manual_retention_roots_topology(
        &self,
        cache_id: i64,
    ) -> Result<Vec<ManualRetentionRootRecord>> {
        self.backend
            .query(
                "SELECT root.id, root.cache_id, root.store_hash,
                   root.protection_kind, lease_head.current_lease_id,
                   root.reason, root.owner_kind, root.owner_id, root.created_by,
                   root.created_at, root.deleted_at, root.resource_version
                 FROM manual_retention_roots root
                 LEFT JOIN manual_retention_lease_heads lease_head
                   ON lease_head.manual_retention_root_id = root.id
                 WHERE root.cache_id = ?1
                 ORDER BY root.created_at DESC, root.id",
                &vals![cache_id],
            )
            .await?
            .iter()
            .map(row_to_manual_retention_root)
            .collect()
    }

    /// Lists deletion jobs for a cache, optionally restricted to an operation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_cache_gc_deletion_jobs_topology(
        &self,
        cache_id: i64,
        operation_id: Option<&str>,
    ) -> Result<Vec<ObjectDeletionJobRecord>> {
        let rows = if let Some(operation_id) = operation_id {
            self.backend
                .query(
                    "SELECT job.job_id, job.cache_id,
                       job.originating_operation_id, job.surface_object_id,
                       job.placement_id, job.phase, job.state,
                       job.attempt_count, job.max_attempts,
                       job.next_attempt_at, job.error_class, job.error,
                       job.confirmed_reclaimed_bytes, job.leaked_bytes,
                       job.resource_version
                     FROM cache_gc_operation_jobs link
                     JOIN object_deletion_jobs job ON job.job_id = link.job_id
                       AND job.cache_id = link.cache_id
                     WHERE link.cache_id = ?1 AND link.operation_id = ?2
                     ORDER BY job.created_at DESC, job.job_id",
                    &vals![cache_id, operation_id],
                )
                .await?
        } else {
            self.backend
                .query(
                    "SELECT job_id, cache_id, originating_operation_id,
                       surface_object_id, placement_id, phase, state,
                       attempt_count, max_attempts, next_attempt_at,
                       error_class, error, confirmed_reclaimed_bytes,
                       leaked_bytes, resource_version
                     FROM object_deletion_jobs WHERE cache_id = ?1
                     ORDER BY created_at DESC, job_id",
                    &vals![cache_id],
                )
                .await?
        };
        rows.iter().map(row_to_object_deletion_job).collect()
    }

    /// Resolves the single plan represented by one cache-GC operation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or inconsistent operation links.
    pub async fn cache_gc_operation_plan_id(
        &self,
        cache_id: i64,
        operation_id: &str,
    ) -> Result<Option<String>> {
        let rows = self
            .backend
            .query(
                "SELECT DISTINCT plan_id FROM cache_gc_operation_jobs
                 WHERE cache_id = ?1 AND operation_id = ?2
                 UNION
                 SELECT plan_id FROM cache_gc_plans
                 WHERE cache_id = ?1 AND operation_id = ?2
                 ORDER BY plan_id",
                &vals![cache_id, operation_id],
            )
            .await?;
        if rows.len() > 1 {
            bail!("cache GC operation is linked to multiple plans");
        }
        rows.first().map(|row| row.get(0)).transpose()
    }

    /// Resolves a deterministic representative store hash for a deletion job.
    ///
    /// Shared NAR actions may belong to multiple store objects; the lowest
    /// canonical hash is returned for the singular display field while
    /// the plan manifest retains every association.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_gc_deletion_job_store_hash(
        &self,
        cache_id: i64,
        job_id: &str,
    ) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT MIN(candidate.store_hash)
                 FROM cache_gc_action_jobs job_link
                 JOIN cache_gc_plan_object_actions object_link
                   ON object_link.cache_id = job_link.cache_id
                  AND object_link.plan_id = job_link.plan_id
                  AND object_link.action_id = job_link.action_id
                 JOIN cache_gc_plan_objects candidate
                   ON candidate.cache_id = object_link.cache_id
                  AND candidate.plan_id = object_link.plan_id
                  AND candidate.cache_object_id = object_link.cache_object_id
                 WHERE job_link.cache_id = ?1 AND job_link.job_id = ?2",
                &vals![cache_id, job_id],
            )
            .await?
            .and_then(|row| row.get::<Option<String>>(0).transpose())
            .transpose()
    }

    /// Returns a persisted GC plan and its complete relational manifest.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn cache_gc_plan_view(
        &self,
        cache_id: i64,
        plan_id: &str,
    ) -> Result<Option<CacheGcPlanView>> {
        let Some(plan) = self
            .backend
            .query_opt(
                "SELECT plan.plan_id, plan.cache_id, plan.generation_id,
                   plan.expected_epoch, generation.gc_policy_version,
                   generation.root_generation,
                   generation.object_graph_generation,
                   generation.topology_version, plan.manifest_digest,
                   plan.confirmation_hash, plan.expires_at
                 FROM cache_gc_plans plan
                 JOIN cache_gc_generations generation
                   ON generation.generation_id = plan.generation_id
                  AND generation.cache_id = plan.cache_id
                 WHERE plan.cache_id = ?1 AND plan.plan_id = ?2",
                &vals![cache_id, plan_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let objects = self
            .backend
            .query(
                "SELECT candidate.cache_object_id, candidate.store_hash,
                   candidate.logical_bytes, candidate.eligibility_reason
                 FROM cache_gc_plan_objects candidate
                 WHERE candidate.cache_id = ?1 AND candidate.plan_id = ?2
                 ORDER BY candidate.cache_object_id",
                &vals![cache_id, plan_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(CacheGcPlanObjectView {
                    cache_object_id: row.get(0)?,
                    store_hash: row.get(1)?,
                    logical_bytes: row.get(2)?,
                    eligibility_reason: row.get(3)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let actions = self
            .backend
            .query(
                "SELECT action.action_id, candidate.store_hash,
                   action.placement_id, action.phase,
                   action.expected_inventory_generation
                 FROM cache_gc_plan_object_actions link
                 JOIN cache_gc_plan_actions action
                   ON action.action_id = link.action_id
                  AND action.cache_id = link.cache_id
                  AND action.plan_id = link.plan_id
                 JOIN cache_gc_plan_objects candidate
                   ON candidate.cache_id = link.cache_id
                  AND candidate.plan_id = link.plan_id
                  AND candidate.cache_object_id = link.cache_object_id
                 WHERE link.cache_id = ?1 AND link.plan_id = ?2
                 ORDER BY action.action_id, candidate.store_hash",
                &vals![cache_id, plan_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(CacheGcPlanActionView {
                    action_id: row.get(0)?,
                    store_hash: row.get(1)?,
                    placement_id: row.get(2)?,
                    phase: row.get(3)?,
                    inventory_generation: row.get(4)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(CacheGcPlanView {
            plan_id: plan.get(0)?,
            cache_id: plan.get(1)?,
            generation_id: plan.get(2)?,
            expected_epoch: plan.get(3)?,
            policy_version: plan.get(4)?,
            root_generation: plan.get(5)?,
            object_graph_generation: plan.get(6)?,
            topology_generation: plan.get(7)?,
            manifest_digest: plan.get(8)?,
            confirmation_hash: plan.get(9)?,
            expires_at: plan.get(10)?,
            objects,
            actions,
        }))
    }

    /// Resolves the owning cache of a stable GC plan id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_gc_plan_view_by_id(&self, plan_id: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT cache_id FROM cache_gc_plans WHERE plan_id = ?1",
                &vals![plan_id],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Returns exact logical accounting captured by a persisted GC plan.
    ///
    /// The tuple is `(scanned, retained, tombstoned, logical_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted accounting.
    pub async fn cache_gc_plan_accounting(
        &self,
        cache_id: i64,
        plan_id: &str,
    ) -> Result<Option<(i64, i64, i64, i64)>> {
        self.backend
            .query_opt(
                "SELECT generation.scanned_object_count,
                   generation.marked_object_count,
                   (SELECT COUNT(*) FROM cache_gc_plan_objects candidate
                     WHERE candidate.cache_id = plan.cache_id
                       AND candidate.plan_id = plan.plan_id),
                   (SELECT COALESCE(SUM(candidate.logical_bytes), 0)
                     FROM cache_gc_plan_objects candidate
                     WHERE candidate.cache_id = plan.cache_id
                       AND candidate.plan_id = plan.plan_id)
                 FROM cache_gc_plans plan
                 JOIN cache_gc_generations generation
                   ON generation.generation_id = plan.generation_id
                  AND generation.cache_id = plan.cache_id
                 WHERE plan.cache_id = ?1 AND plan.plan_id = ?2",
                &vals![cache_id, plan_id],
            )
            .await?
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .transpose()
    }

    /// Builds and persists a complete mark generation and reviewed GC plan.
    ///
    /// The closure walk, generation publication, candidate selection, and
    /// relational physical manifest all pass through the same fail-closed
    /// contracts used by controller-driven planning.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete closure coverage, stale topology or
    /// inventory, malformed physical evidence, or database failure.
    pub async fn build_cache_gc_plan_topology(
        &self,
        cache_id: i64,
        actor_scope_digest: &str,
        created_by: &str,
        request_idempotency_key: &str,
        request_digest: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<CacheGcPlanView> {
        self.assert_cache_gc_delete_topology_supported(cache_id)
            .await?;
        if actor_scope_digest.is_empty()
            || created_by.trim().is_empty()
            || request_idempotency_key.is_empty()
            || request_idempotency_key.len() > 128
            || request_digest.is_empty()
            || expires_at <= now
        {
            bail!("cache GC planner requires actor scope, principal, and a future expiry");
        }
        if let Some(existing) = self
            .backend
            .query_opt(
                "SELECT plan_id, request_digest FROM cache_gc_plans
                 WHERE cache_id = ?1 AND actor_scope_digest = ?2
                   AND request_idempotency_key = ?3",
                &vals![cache_id, actor_scope_digest, request_idempotency_key],
            )
            .await?
        {
            let existing_digest: String = existing.get(1)?;
            if existing_digest != request_digest {
                bail!("cache GC idempotency key was already used for another request");
            }
            let existing_plan_id: String = existing.get(0)?;
            return self
                .cache_gc_plan_view(cache_id, &existing_plan_id)
                .await?
                .context("idempotent cache GC plan disappeared");
        }
        let state = self
            .cache_gc_topology_state(cache_id)
            .await?
            .context("cache GC topology is not initialized")?;
        let plan_id = digest_text(&format!(
            "cache-gc-plan:{cache_id}:{actor_scope_digest}:{request_idempotency_key}"
        ));
        let generation_id = digest_text(&format!("cache-gc-generation:{plan_id}"));
        let generation_state = self
            .backend
            .query_opt(
                "SELECT state FROM cache_gc_generations
                 WHERE cache_id = ?1 AND generation_id = ?2",
                &vals![cache_id, generation_id],
            )
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?;
        if generation_state.is_none() {
            self.begin_cache_gc_generation(&BeginCacheGcGeneration {
                generation_id: generation_id.clone(),
                cache_id,
                cutoff_at: now,
                expected_epoch: state.epoch,
                created_at: now,
            })
            .await?;
        } else if generation_state.as_deref() == Some("failed") {
            bail!("idempotent cache GC mark generation previously failed");
        }
        if generation_state.as_deref() != Some("complete") {
            let closure = Statement::new(
                "INSERT INTO cache_gc_marks
             (cache_id, generation_id, cache_object_id)
             WITH RECURSIVE closure(cache_object_id) AS (
               SELECT object.id
               FROM cache_gc_generation_roots root
               JOIN cache_objects object ON object.cache_id = root.cache_id
                 AND object.store_hash = root.store_hash
                 AND object.lifecycle_state = 'active'
               WHERE root.cache_id = ?1 AND root.generation_id = ?2
               UNION
               SELECT edge.referenced_cache_object_id
               FROM closure reachable
               JOIN cache_object_references edge
                 ON edge.cache_id = ?1
                AND edge.cache_object_id = reachable.cache_object_id
               JOIN cache_objects referenced
                 ON referenced.id = edge.referenced_cache_object_id
                AND referenced.cache_id = edge.cache_id
                AND referenced.lifecycle_state = 'active'
             )
             SELECT ?1, ?2, closure.cache_object_id FROM closure
             WHERE NOT EXISTS (SELECT 1 FROM cache_gc_marks existing
               WHERE existing.cache_id = ?1 AND existing.generation_id = ?2
                 AND existing.cache_object_id = closure.cache_object_id)",
                vals![cache_id, generation_id],
            )
            .unchecked();
            self.backend.checked_batch(&[closure]).await?;
            if let Err(error) = self
                .complete_cache_gc_generation(cache_id, &generation_id, now)
                .await
            {
                let detail = format!("closure publication failed: {error:#}");
                let _ = self
                    .fail_cache_gc_generation(cache_id, &generation_id, &detail, now)
                    .await;
                return Err(error);
            }
        }

        let policy = self
            .cache_gc_policy_topology(cache_id)
            .await?
            .context("cache GC policy disappeared")?;
        let totals = self
            .backend
            .query_opt(
                "SELECT COALESCE(SUM(file_size), 0), COUNT(*)
                 FROM cache_objects
                 WHERE cache_id = ?1 AND lifecycle_state = 'active'",
                &vals![cache_id],
            )
            .await?
            .context("cache object totals query returned no row")?;
        let total_bytes: i64 = totals.get(0)?;
        let total_objects: i64 = totals.get(1)?;
        let over_bytes = policy
            .soft_max_bytes
            .is_some_and(|limit| total_bytes > limit);
        let over_objects = policy
            .soft_max_objects
            .is_some_and(|limit| total_objects > limit);
        let candidate_rows = self
            .backend
            .query(
                "SELECT object.id, object.store_hash, object.resource_version,
                   object.unreferenced_since, object.file_size,
                   object.narinfo_surface_object_id,
                   object.nar_surface_object_id
                 FROM cache_objects object
                 WHERE object.cache_id = ?1 AND object.lifecycle_state = 'active'
                   AND object.unreferenced_since IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM cache_gc_marks mark
                     WHERE mark.cache_id = ?1 AND mark.generation_id = ?2
                       AND mark.cache_object_id = object.id)
                 ORDER BY object.unreferenced_since, object.id",
                &vals![cache_id, generation_id],
            )
            .await?;
        let mut objects = Vec::new();
        let mut object_surfaces = BTreeMap::new();
        for row in candidate_rows {
            let unreferenced_since: i64 = row.get(3)?;
            if unreferenced_since
                .checked_add(policy.unreferenced_grace_secs)
                .context("cache GC grace deadline overflowed")?
                > now
            {
                continue;
            }
            let eligibility_reason = if over_bytes {
                "byte_cap"
            } else if over_objects {
                "object_cap"
            } else {
                "ttl"
            };
            let cache_object_id: i64 = row.get(0)?;
            let narinfo_surface_object_id: i64 = row.get(5)?;
            let nar_surface_object_id: i64 = row.get(6)?;
            object_surfaces.insert(
                cache_object_id,
                (narinfo_surface_object_id, nar_surface_object_id),
            );
            objects.push(CacheGcPlanObjectInput {
                cache_object_id,
                store_hash: row.get(1)?,
                expected_object_version: row.get(2)?,
                expected_unreferenced_since: unreferenced_since,
                eligibility_reason: eligibility_reason.to_string(),
                logical_bytes: row.get(4)?,
            });
        }
        let selected = objects
            .iter()
            .map(|object| object.cache_object_id)
            .collect::<BTreeSet<_>>();
        let mut action_by_placement = BTreeMap::<(i64, i64), CacheGcPlanActionInput>::new();
        let mut object_action_keys = BTreeSet::new();
        let mut narinfo_by_object_placement = BTreeMap::new();
        let mut nar_by_object_placement = BTreeMap::new();
        let mut deletion_capabilities = BTreeMap::<i64, (i64, i64, i64)>::new();
        for object in &objects {
            let (narinfo_surface_object_id, nar_surface_object_id) = object_surfaces
                .get(&object.cache_object_id)
                .copied()
                .context("cache GC candidate lost its surface identities")?;
            let shared_by_unselected = self
                .backend
                .query(
                    "SELECT id FROM cache_objects
                     WHERE cache_id = ?1 AND nar_surface_object_id = ?2
                       AND lifecycle_state = 'active' AND id <> ?3",
                    &vals![cache_id, nar_surface_object_id, object.cache_object_id],
                )
                .await?
                .iter()
                .map(|row| row.get::<i64>(0))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|id| !selected.contains(&id));
            let presences = self
                .backend
                .query(
                    "SELECT surface_object_id, placement_id, state,
                       observed_hash, observed_size, etag,
                       observed_inventory_generation
                     FROM object_placements
                     WHERE cache_id = ?1
                       AND (surface_object_id = ?2 OR surface_object_id = ?3)
                       AND state <> 'missing'
                     ORDER BY placement_id, surface_object_id",
                    &vals![cache_id, narinfo_surface_object_id, nar_surface_object_id],
                )
                .await?;
            for presence in presences {
                let surface_object_id: i64 = presence.get(0)?;
                if surface_object_id == nar_surface_object_id && shared_by_unselected {
                    continue;
                }
                let placement_id: i64 = presence.get(1)?;
                let phase = if surface_object_id == narinfo_surface_object_id {
                    "narinfo"
                } else {
                    "nar"
                };
                let key = (surface_object_id, placement_id);
                let expected_etag: Option<String> = presence.get(5)?;
                let expected_hash: Option<String> = presence.get(3)?;
                let expected_size: Option<i64> = presence.get(4)?;
                let expected_inventory_generation: i64 = presence.get(6)?;
                let deletion_capability =
                    if let Some(capability) = deletion_capabilities.get(&placement_id) {
                        Some(*capability)
                    } else {
                        let capability = self
                            .backend
                            .query_opt(
                                "SELECT binding.id, binding.resource_version,
                                   credential.generation
                             FROM surface_placements placement
                             JOIN bindings binding
                               ON binding.id = placement.binding_id
                             JOIN cache_inventory_placement_scans scan
                               ON scan.cache_id = placement.cache_id
                              AND scan.placement_id = placement.id
                              AND scan.generation = ?3
                             JOIN binding_credential_heads head
                               ON head.binding_id = binding.id
                              AND head.purpose = 'delete'
                             JOIN binding_credential_revisions credential
                               ON credential.binding_id = head.binding_id
                              AND credential.purpose = head.purpose
                              AND credential.generation = head.current_generation
                             WHERE placement.id = ?1 AND placement.cache_id = ?2
                               AND binding.kind = 's3'
                               AND binding.is_instance_default = 0
                               AND scan.completed_at IS NOT NULL
                               AND scan.binding_id = binding.id
                               AND scan.binding_resource_version = binding.resource_version
                               AND credential.validation_state = 'valid'",
                                &vals![placement_id, cache_id, expected_inventory_generation],
                            )
                            .await?
                            .map(|row| -> Result<(i64, i64, i64)> {
                                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                            })
                            .transpose()?;
                        if let Some(capability) = capability {
                            deletion_capabilities.insert(placement_id, capability);
                        }
                        capability
                    };
                let Some((binding_id, binding_resource_version, delete_credential_generation)) =
                    deletion_capability
                else {
                    bail!(
                        "placement {placement_id} cannot enforce identity-checked deletion; migrate it to a validated S3 binding before enabling destructive GC"
                    );
                };
                if expected_etag
                    .as_deref()
                    .is_none_or(|etag| crate::surface_write::strong_if_match_etag(etag).is_err())
                {
                    bail!(
                        "placement {placement_id} has no strong ETag for surface object {surface_object_id}; refresh complete inventory before planning GC"
                    );
                }
                let action =
                    action_by_placement
                        .entry(key)
                        .or_insert_with(|| CacheGcPlanActionInput {
                            action_id: digest_text(&format!(
                                "cache-gc-action:{plan_id}:{surface_object_id}:{placement_id}"
                            )),
                            surface_object_id,
                            placement_id,
                            phase: phase.to_string(),
                            expected_etag,
                            expected_hash,
                            expected_size,
                            expected_inventory_generation,
                            binding_id,
                            binding_resource_version,
                            delete_credential_generation,
                            estimated_reclaimable_bytes: expected_size.unwrap_or_default(),
                        });
                object_action_keys.insert((object.cache_object_id, action.action_id.clone()));
                if phase == "narinfo" {
                    narinfo_by_object_placement.insert(
                        (object.cache_object_id, placement_id),
                        action.action_id.clone(),
                    );
                } else {
                    nar_by_object_placement.insert(
                        (object.cache_object_id, placement_id),
                        action.action_id.clone(),
                    );
                }
            }
        }
        let mut actions = action_by_placement.into_values().collect::<Vec<_>>();
        actions.sort_by(|left, right| left.action_id.cmp(&right.action_id));
        let object_actions = object_action_keys
            .into_iter()
            .map(
                |(cache_object_id, action_id)| CacheGcPlanObjectActionInput {
                    cache_object_id,
                    action_id,
                },
            )
            .collect::<Vec<_>>();
        let mut dependencies = BTreeSet::new();
        for ((cache_object_id, placement_id), action_id) in nar_by_object_placement {
            let prerequisite_action_id = narinfo_by_object_placement
                .get(&(cache_object_id, placement_id))
                .context("NAR deletion has no same-placement narinfo prerequisite")?;
            dependencies.insert((action_id, prerequisite_action_id.clone()));
        }
        let dependencies = dependencies
            .into_iter()
            .map(
                |(action_id, prerequisite_action_id)| CacheGcActionDependencyInput {
                    action_id,
                    prerequisite_action_id,
                },
            )
            .collect::<Vec<_>>();
        let input_versions_digest = self
            .cache_gc_generation_input_versions_digest(cache_id, &generation_id)
            .await?;
        let mut plan = CreateCacheGcPlan {
            plan_id: plan_id.clone(),
            cache_id,
            generation_id,
            expected_epoch: state.epoch,
            input_versions_digest,
            manifest_digest: String::new(),
            actor_scope_digest: actor_scope_digest.to_string(),
            confirmation_hash: String::new(),
            created_by: created_by.to_string(),
            request_idempotency_key: request_idempotency_key.to_string(),
            request_digest: request_digest.to_string(),
            created_at: now,
            expires_at,
            objects,
            actions,
            object_actions,
            dependencies,
        };
        plan.manifest_digest = cache_gc_manifest_digest(&plan)?;
        plan.confirmation_hash = digest_text(&format!(
            "plan={};inputs={};manifest={};actor_scope={};expires_at={}",
            plan.plan_id,
            plan.input_versions_digest,
            plan.manifest_digest,
            plan.actor_scope_digest,
            plan.expires_at
        ));
        self.create_cache_gc_plan_topology(&plan).await?;
        self.cache_gc_plan_view(cache_id, &plan_id)
            .await?
            .context("created cache GC plan disappeared")
    }
}

fn epoch_update_statement(
    cache_id: i64,
    expected_epoch: i64,
    mutation_id: &str,
    generation_update: &str,
) -> CheckedStatement {
    Statement::new(
        format!(
            "UPDATE cache_gc_state SET epoch = epoch + 1,
             epoch_owner_token = ?3, {generation_update},
             resource_version = resource_version + 1
             WHERE cache_id = ?1 AND epoch = ?2"
        ),
        vals![cache_id, expected_epoch, mutation_id],
    )
    .expecting(1)
}

fn epoch_assertion_statement(
    mutation_id: &str,
    cache_id: i64,
    expected_epoch: i64,
    mutation_kind: &str,
    now: i64,
    domain_predicate: &str,
) -> CheckedStatement {
    Statement::new(
        format!(
            "INSERT INTO cache_gc_epoch_assertions
             (mutation_id, cache_id, expected_epoch, resulting_epoch,
              epoch_owner_token, mutation_kind, ok, asserted_at)
             VALUES (?1, ?2, ?3, ?3 + 1, ?1, ?4,
               CASE WHEN EXISTS (SELECT 1 FROM cache_gc_state
                 WHERE cache_id = ?2 AND epoch = ?3 + 1
                   AND epoch_owner_token = ?1) AND ({domain_predicate})
                 THEN 1 ELSE 0 END, ?5)"
        ),
        vals![mutation_id, cache_id, expected_epoch, mutation_kind, now],
    )
    .expecting(1)
}

fn sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

const CACHE_OBJECT_RECORD_COLUMNS: &str = "object.id, object.cache_id, \
    object.store_hash, object.store_name, object.narinfo_surface_object_id, \
    object.nar_surface_object_id, nar.object_key, object.nar_hash, \
    object.nar_size, object.file_hash, object.file_size, object.compression, \
    object.deriver, object.signature, object.content_address, \
    object.published_at, object.last_access_observed_at, object.resource_version";

fn row_to_cache_gc_state(row: &Row) -> Result<CacheGcStateRecord> {
    Ok(CacheGcStateRecord {
        cache_id: row.get(0)?,
        epoch: row.get(1)?,
        epoch_owner_token: row.get(2)?,
        root_generation: row.get(3)?,
        object_graph_generation: row.get(4)?,
        inventory_generation: row.get(5)?,
        topology_generation: row.get(6)?,
        current_mark_generation_id: row.get(7)?,
        destructive_enabled: row.get(8)?,
        resource_version: row.get(9)?,
    })
}

const RETENTION_SUBSCRIPTION_COLUMNS: &str = "subscription.id, subscription.cache_id, \
    subscription.registry_id, subscription.selector_json, subscription.selector_digest, \
    subscription.removal_grace_secs, subscription.exposure_acknowledged_at, \
    subscription.enabled, subscription.last_successful_revision, \
    subscription.last_refresh_at, head.current_refresh_id, subscription.refresh_state, \
    subscription.refresh_error, subscription.retired_at, subscription.resource_version, \
    subscription.created_at, subscription.updated_at";

fn row_to_cache_retention_subscription(row: &Row) -> Result<CacheRetentionSubscriptionRecord> {
    Ok(CacheRetentionSubscriptionRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        registry_id: row.get(2)?,
        selector_json: row.get(3)?,
        selector_digest: row.get(4)?,
        removal_grace_secs: row.get(5)?,
        exposure_acknowledged_at: row.get(6)?,
        enabled: row.get(7)?,
        last_successful_revision: row.get(8)?,
        last_refresh_at: row.get(9)?,
        current_refresh_id: row.get(10)?,
        refresh_state: row.get(11)?,
        refresh_error: row.get(12)?,
        retired_at: row.get(13)?,
        resource_version: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

fn row_to_manual_retention_root(row: &Row) -> Result<ManualRetentionRootRecord> {
    Ok(ManualRetentionRootRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        store_hash: row.get(2)?,
        protection_kind: row.get(3)?,
        current_lease_id: row.get(4)?,
        reason: row.get(5)?,
        owner_kind: row.get(6)?,
        owner_id: row.get(7)?,
        created_by: row.get(8)?,
        created_at: row.get(9)?,
        deleted_at: row.get(10)?,
        resource_version: row.get(11)?,
    })
}

fn row_to_retention_lease(row: &Row) -> Result<RetentionLeaseRecord> {
    Ok(RetentionLeaseRecord {
        id: row.get(0)?,
        manual_retention_root_id: row.get(1)?,
        begins_at: row.get(2)?,
        expires_at: row.get(3)?,
        renewed_from_lease_id: row.get(4)?,
        state: row.get(5)?,
        renewed_by: row.get(6)?,
        renewed_at: row.get(7)?,
        revoked_by: row.get(8)?,
        revoked_at: row.get(9)?,
        resource_version: row.get(10)?,
    })
}

fn row_to_cache_root_reason(row: &Row) -> Result<CacheRootReasonRecord> {
    Ok(CacheRootReasonRecord {
        id: row.get(0)?,
        cache_id: row.get(1)?,
        registry_id: row.get(2)?,
        store_hash: row.get(3)?,
        reason_key: row.get(4)?,
        source_kind: row.get(5)?,
        refresh_id: row.get(6)?,
        retention_subscription_id: row.get(7)?,
        manual_retention_root_id: row.get(8)?,
        retention_lease_id: row.get(9)?,
        release_id: row.get(10)?,
        release_snapshot_id: row.get(11)?,
        channel_id: row.get(12)?,
        partition_bucket: row.get(13)?,
        source_ref: row.get(14)?,
        source_revision: row.get(15)?,
        expires_at: row.get(16)?,
        refreshed_at: row.get(17)?,
    })
}

fn row_to_object_deletion_job(row: &Row) -> Result<ObjectDeletionJobRecord> {
    Ok(ObjectDeletionJobRecord {
        job_id: row.get(0)?,
        cache_id: row.get(1)?,
        operation_id: row.get(2)?,
        surface_object_id: row.get(3)?,
        placement_id: row.get(4)?,
        phase: row.get(5)?,
        state: row.get(6)?,
        attempt_count: row.get(7)?,
        max_attempts: row.get(8)?,
        next_attempt_at: row.get(9)?,
        error_class: row.get(10)?,
        error: row.get(11)?,
        confirmed_reclaimed_bytes: row.get(12)?,
        leaked_bytes: row.get(13)?,
        resource_version: row.get(14)?,
    })
}

/// Builds the quota half of an atomic quota-reservation/write-ticket batch.
///
/// Every organization gets an `org_usage` row at creation. Keeping this update
/// in the same checked batch as the ticket insert means a crash leaves either
/// both absent or both present, never charged usage without its durable
/// recovery owner.
fn quota_reservation_statements(
    org_id: Option<i64>,
    delta_bytes: i64,
    delta_objects: i64,
    now: i64,
) -> Vec<CheckedStatement> {
    let Some(org_id) = org_id else {
        return Vec::new();
    };
    vec![Statement::new(
        "UPDATE org_usage
         SET used_bytes = CASE WHEN used_bytes + ?2 < 0 THEN 0
               ELSE used_bytes + ?2 END,
             object_count = CASE WHEN object_count + ?3 < 0 THEN 0
               ELSE object_count + ?3 END,
             updated_at = ?4
         WHERE org_id = ?1
           AND ((SELECT max_bytes FROM org_quotas WHERE org_id = ?1) IS NULL
             OR (CASE WHEN used_bytes + ?2 < 0 THEN 0 ELSE used_bytes + ?2 END)
               <= (SELECT max_bytes FROM org_quotas WHERE org_id = ?1))
           AND ((SELECT max_objects FROM org_quotas WHERE org_id = ?1) IS NULL
             OR (CASE WHEN object_count + ?3 < 0 THEN 0 ELSE object_count + ?3 END)
               <= (SELECT max_objects FROM org_quotas WHERE org_id = ?1))",
        vals![org_id, delta_bytes, delta_objects, now],
    )
    .expecting(1)]
}

fn row_to_cache_write_ticket(row: &Row) -> Result<CacheWriteTicketRecord> {
    Ok(CacheWriteTicketRecord {
        ticket_id: row.get(0)?,
        cache_id: row.get(1)?,
        object_key: row.get(2)?,
        declared_size: row.get(3)?,
        observed_final_size: row.get(4)?,
        uploaded_size: row.get(5)?,
        upload_kind: row.get(6)?,
        placement_id: row.get(7)?,
        placement_resource_version: row.get(8)?,
        placement_write_spec_version: row.get(9)?,
        binding_id: row.get(10)?,
        binding_resource_version: row.get(11)?,
        binding_write_revision: row.get(12)?,
        write_credential_purpose: row.get(13)?,
        write_credential_generation: row.get(14)?,
        presign_credential_purpose: row.get(15)?,
        presign_credential_generation: row.get(16)?,
        starting_inventory_generation: row.get(17)?,
        covered_inventory_generation: row.get(18)?,
        backend_upload_id: row.get(19)?,
        state: row.get(20)?,
        expires_at: row.get(21)?,
        resource_version: row.get(22)?,
        prior_object: row_to_write_object_identity(row, 23, 24, 25)?,
        intended_object_hash: row.get(26)?,
    })
}

fn row_to_write_object_identity(
    row: &Row,
    size_index: usize,
    hash_index: usize,
    etag_index: usize,
) -> Result<Option<WriteObjectIdentity>> {
    let size = row.get::<Option<i64>>(size_index)?;
    let sha256 = row.get::<Option<String>>(hash_index)?;
    let strong_etag = row.get::<Option<String>>(etag_index)?;
    match (size, sha256) {
        (None, None) if strong_etag.is_none() => Ok(None),
        (Some(size), Some(sha256)) => Ok(Some(WriteObjectIdentity {
            size,
            sha256,
            strong_etag,
        })),
        _ => bail!("persisted write ticket has an incomplete prior object identity"),
    }
}

fn row_to_write_ticket_part(row: &Row) -> Result<WriteTicketPartRecord> {
    let part_number = u32::try_from(row.get::<i64>(0)?)
        .context("multipart part number is outside the u32 range")?;
    Ok(WriteTicketPartRecord {
        part_number,
        admitted_size: row.get(1)?,
        body_digest: row.get(2)?,
        state: row.get(3)?,
        etag: row.get(4)?,
    })
}

fn validate_part_body_identity(part_number: u32, part_size: i64, body_digest: &str) -> Result<()> {
    if !(1..=10_000).contains(&part_number)
        || part_size <= 0
        || body_digest.len() != 64
        || !body_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("multipart part body identity is invalid");
    }
    Ok(())
}

fn validate_write_identities(
    prior_object: Option<&WriteObjectIdentity>,
    intended_object_hash: Option<&str>,
) -> Result<()> {
    let valid_hash = |hash: &str| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    if prior_object.is_some_and(|identity| identity.size < 0 || !valid_hash(&identity.sha256))
        || intended_object_hash.is_some_and(|hash| !valid_hash(hash))
    {
        bail!("write object identity is invalid");
    }
    Ok(())
}

fn require_same_part_body(
    existing: &WriteTicketPartRecord,
    part_size: i64,
    body_digest: &str,
) -> Result<()> {
    if existing.admitted_size != part_size || existing.body_digest != body_digest {
        bail!("multipart part number was already admitted with different bytes");
    }
    Ok(())
}

fn row_to_object_deletion_attempt_receipt(row: &Row) -> Result<ObjectDeletionAttemptReceipt> {
    Ok(ObjectDeletionAttemptReceipt {
        request_id: row.get(0)?,
        cache_id: row.get(1)?,
        job_id: row.get(2)?,
        attempt_number: row.get(3)?,
        placement_id: row.get(4)?,
        surface_object_id: row.get(5)?,
        object_key: row.get(6)?,
        expected_etag: row.get(7)?,
        expected_hash: row.get(8)?,
        expected_size: row.get(9)?,
        expected_inventory_generation: row.get(10)?,
        binding_id: row.get(11)?,
        binding_resource_version: row.get(12)?,
        delete_credential_generation: row.get(13)?,
        state: row.get(14)?,
        outcome: row.get(15)?,
        response_etag: row.get(16)?,
        response_hash: row.get(17)?,
        response_size: row.get(18)?,
        error_class: row.get(19)?,
        response_detail: row.get(20)?,
        requested_at: row.get(21)?,
        responded_at: row.get(22)?,
        finalized_at: row.get(23)?,
    })
}

#[cfg(any(test, feature = "do-e2e-test-support"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TestWriteTicketSettlement {
    pub(crate) state: String,
    pub(crate) quota_state: String,
    pub(crate) active_slot: Option<i64>,
    pub(crate) covered_inventory_generation: Option<i64>,
    pub(crate) recovery_attempts: i64,
    pub(crate) finished_at: Option<i64>,
}

#[cfg(any(test, feature = "do-e2e-test-support"))]
impl Database {
    /// Installs the disposable live-workerd topology fixture.
    ///
    /// This method exists only in tests and the non-default
    /// `do-e2e-test-support` feature used by the workerd integration artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when fixture insertion fails.
    #[cfg(any(test, feature = "do-e2e-test-support"))]
    pub async fn install_do_e2e_topology_fixture(&self) -> Result<()> {
        self.install_write_failure_test_tickets().await?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key,
                      resource_stable_id, created_at)
                     VALUES
                       ('cache:00000000000000000000000000000002', 'binary_cache',
                        1, 'org:00000000000000000000000000000001',
                        'cache:00000000000000000000000000000002', 1),
                       ('registry:00000000000000000000000000000002', 'registry',
                        1, 'org:00000000000000000000000000000001',
                        'registry:00000000000000000000000000000002', 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES
                       ('cache:00000000000000000000000000000002',
                        'cache:00000000000000000000000000000002', 0),
                       ('cache:00000000000000000000000000000002',
                        'org:00000000000000000000000000000001', 1),
                       ('cache:00000000000000000000000000000002', 'instance', 2),
                       ('registry:00000000000000000000000000000002',
                        'registry:00000000000000000000000000000002', 0),
                       ('registry:00000000000000000000000000000002',
                        'org:00000000000000000000000000000001', 1),
                       ('registry:00000000000000000000000000000002', 'instance', 2)",
                    vec![],
                )
                .expecting(6),
                Statement::new(
                    "INSERT INTO binary_caches
                     (id, stable_id, org_id, slug, name, visibility, created_at,
                      scope_key, owner_scope_key)
                     VALUES (2, 'cache:00000000000000000000000000000002', 1,
                       'flat-cache', 'Flat cache', 'private', 1,
                       'cache:00000000000000000000000000000002',
                       'org:00000000000000000000000000000001')",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registries
                     (id, stable_id, org_id, slug, created_at, scope_key, owner_scope_key)
                     VALUES (2, 'registry:00000000000000000000000000000002', 1,
                       'flat-registry', 1,
                       'registry:00000000000000000000000000000002',
                       'org:00000000000000000000000000000001')",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, cache_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, prefix, kind, desired_state,
                      created_at, updated_at)
                     VALUES (3, 2, 'flat-cache', 1,
                       'org:00000000000000000000000000000001', 1, 'flat-cache/',
                       'complete', 'active', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, registry_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, prefix, kind, desired_state,
                      created_at, updated_at)
                     VALUES (4, 2, 'flat-registry', 1,
                       'org:00000000000000000000000000000001', 1, 'flat-registry/',
                       'complete', 'active', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_inventory_generations
                     (cache_id, generation, owner_token, lease_expires_at,
                      state, content_digest, published_at, created_at)
                     VALUES (2, 1, 'bootstrap', 2,
                       'published', 'flat-cache-inventory', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_gc_state
                     (cache_id, epoch, epoch_owner_token, inventory_generation)
                     VALUES (2, 0, 'bootstrap', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placement_observations
                     (placement_id, state, completeness, observed_at,
                      observation_version)
                     VALUES
                       (3, 'ready', 'complete', 1, 1),
                       (4, 'ready', 'complete', 1, 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO surface_placement_write_capabilities
                     (placement_id, placement_write_spec_version,
                      binding_id, binding_write_revision, created_at)
                     VALUES (3, 1, 1, 1, 1), (4, 1, 1, 1, 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO surface_write_authorities
                     (id, incarnation_id, cache_id, desired_placement_id,
                      desired_write_spec_version, desired_binding_write_revision,
                      desired_generation, observed_placement_id,
                      observed_write_spec_version, observed_binding_write_revision,
                      observed_generation, reconciliation_state, created_at, updated_at)
                     VALUES (3, 'flat-cache-authority', 2, 3, 1, 1, 1,
                       3, 1, 1, 1, 'ready', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_write_authorities
                     (id, incarnation_id, registry_id, desired_placement_id,
                      desired_write_spec_version, desired_binding_write_revision,
                      desired_generation, observed_placement_id,
                      observed_write_spec_version, observed_binding_write_revision,
                      observed_generation, reconciliation_state, created_at, updated_at)
                     VALUES (4, 'flat-registry-authority', 2, 4, 1, 1, 1,
                       4, 1, 1, 1, 'ready', 1, 1)",
                    vec![],
                )
                .expecting(1),
            ])
            .await
    }

    /// Installs cache and registry tickets for write-failure settlement tests.
    pub(crate) async fn install_write_failure_test_tickets(&self) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO orgs
                     (id, stable_id, slug, name, created_at)
                     VALUES (1, 'org:00000000000000000000000000000001',
                       'failure', 'Failure organization', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key,
                      resource_stable_id, created_at)
                     VALUES ('org:00000000000000000000000000000001',
                       'organization', 1, 'instance',
                       'org:00000000000000000000000000000001', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key,
                      resource_stable_id, created_at)
                     VALUES
                       ('cache:00000000000000000000000000000001', 'binary_cache',
                        1, 'org:00000000000000000000000000000001',
                        'cache:00000000000000000000000000000001', 1),
                       ('registry:00000000000000000000000000000001', 'registry',
                        1, 'org:00000000000000000000000000000001',
                        'registry:00000000000000000000000000000001', 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES
                       ('org:00000000000000000000000000000001',
                        'org:00000000000000000000000000000001', 0),
                       ('org:00000000000000000000000000000001', 'instance', 1),
                       ('cache:00000000000000000000000000000001',
                        'cache:00000000000000000000000000000001', 0),
                       ('cache:00000000000000000000000000000001',
                        'org:00000000000000000000000000000001', 1),
                       ('cache:00000000000000000000000000000001', 'instance', 2),
                       ('registry:00000000000000000000000000000001',
                        'registry:00000000000000000000000000000001', 0),
                       ('registry:00000000000000000000000000000001',
                        'org:00000000000000000000000000000001', 1),
                       ('registry:00000000000000000000000000000001', 'instance', 2)",
                    vec![],
                )
                .expecting(8),
                Statement::new(
                    "INSERT INTO binary_caches
                     (id, stable_id, org_id, slug, name, visibility, created_at,
                      scope_key, owner_scope_key)
                     VALUES (1, 'cache:00000000000000000000000000000001', 1,
                       'failure/cache', 'Failure cache', 'private', 1,
                       'cache:00000000000000000000000000000001',
                       'org:00000000000000000000000000000001')",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registries
                     (id, stable_id, org_id, slug, created_at, scope_key, owner_scope_key)
                     VALUES (1, 'registry:00000000000000000000000000000001', 1,
                       'failure/registry', 1,
                       'registry:00000000000000000000000000000001',
                       'org:00000000000000000000000000000001')",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO bindings
                     (id, org_id, name, kind, is_instance_default,
                      created_at, stable_id, owner_scope_key, object_bucket,
                      object_prefix, endpoint_scheme, endpoint_host_kind,
                      endpoint_host_bytes, endpoint_port, signing_region,
                      access_mode, resource_version, updated_at)
                     VALUES (1, 1, 'failure-store', 's3', 0, 1,
                       'binding:failure-store',
                       'org:00000000000000000000000000000001', 'failure-bucket', '',
                       'https', 'dns', CAST('storage.example.test' AS BLOB), 443,
                       'us-test-1', 'private', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_credential_revisions
                     (binding_id, purpose, generation, secret_version_ref,
                      validation_state, validated_at, credential_fingerprint,
                      created_by, created_at)
                     VALUES
                       (1, 'write', 1, 'write-secret', 'valid', 1,
                        'write-fingerprint', 'test', 1),
                       (1, 'presign', 1, 'presign-secret', 'valid', 1,
                        'presign-fingerprint', 'test', 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO binding_credential_heads
                     (binding_id, purpose, current_generation,
                      resource_version, updated_at)
                     VALUES (1, 'presign', 1, 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_write_revisions
                     (binding_id, revision, write_credential_version_ref,
                      writes_supported, conditional_writes_supported,
                      revision_fingerprint, capability_fingerprint, created_at,
                      write_credential_purpose, write_credential_generation)
                     VALUES (1, 1, 'write-secret', 1, 1,
                       'write-revision', 'write-capability', 1, 'write', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_write_observations
                     (binding_id, revision, state, validated_at,
                      observation_version)
                     VALUES (1, 1, 'valid', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_consumer_scopes
                     (binding_id, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     VALUES (1, 'org:00000000000000000000000000000001', 1,
                       'owner', 'active',
                       'test', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, cache_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, prefix, kind, desired_state,
                      created_at, updated_at)
                     VALUES (1, 1, 'cache', 1,
                       'org:00000000000000000000000000000001', 1, 'cache/',
                       'complete', 'active', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, registry_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, prefix, kind, desired_state,
                      created_at, updated_at)
                     VALUES (2, 1, 'registry', 1,
                       'org:00000000000000000000000000000001', 1, 'registry/',
                       'complete', 'active', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new("INSERT INTO org_quotas (org_id) VALUES (1)", vec![]).expecting(1),
                Statement::new(
                    "INSERT INTO org_usage
                     (org_id, used_bytes, object_count, updated_at)
                     VALUES (1, 0, 0, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_inventory_generations
                     (cache_id, generation, owner_token, lease_expires_at,
                      state, content_digest, published_at, created_at)
                     VALUES (1, 1, 'bootstrap', 2,
                       'published', 'failure-inventory', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placement_observations
                     (placement_id, state, completeness, observed_at,
                      observation_version)
                     VALUES
                       (1, 'ready', 'complete', 1, 1),
                       (2, 'ready', 'complete', 1, 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO surface_placement_write_capabilities
                     (placement_id, placement_write_spec_version,
                      binding_id, binding_write_revision, created_at)
                     VALUES (1, 1, 1, 1, 1), (2, 1, 1, 1, 1)",
                    vec![],
                )
                .expecting(2),
                Statement::new(
                    "INSERT INTO surface_write_authorities
                     (id, incarnation_id, cache_id, desired_placement_id,
                      desired_write_spec_version, desired_binding_write_revision,
                      desired_generation, observed_placement_id,
                      observed_write_spec_version, observed_binding_write_revision,
                      observed_generation, reconciliation_state, created_at, updated_at)
                     VALUES (1, 'cache-authority', 1, 1, 1, 1, 1,
                       1, 1, 1, 1, 'ready', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_write_authorities
                     (id, incarnation_id, registry_id, desired_placement_id,
                      desired_write_spec_version, desired_binding_write_revision,
                      desired_generation, observed_placement_id,
                      observed_write_spec_version, observed_binding_write_revision,
                      observed_generation, reconciliation_state, created_at, updated_at)
                     VALUES (2, 'registry-authority', 1, 2, 1, 1, 1,
                       2, 1, 1, 1, 'ready', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_gc_state
                     (cache_id, epoch, epoch_owner_token, inventory_generation)
                     VALUES (1, 0, 'bootstrap', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_gc_deletion_capacity (cache_id, running_count)
                     VALUES (1, 0)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_gc_heads (cache_id, resource_version, updated_at)
                     VALUES (1, 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_gc_policies
                     (cache_id, unreferenced_grace_secs, schedule_secs,
                      deletion_concurrency, retry_initial_secs, retry_max_secs,
                      retry_max_attempts, tombstone_retention_secs, resource_version)
                     VALUES (1, 604800, 86400, 4, 60, 3600, 10, 2592000, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO cache_write_tickets
                     (ticket_id, cache_id, object_key, declared_size, upload_kind,
                      placement_id, placement_resource_version,
                      placement_write_spec_version, binding_id,
                      binding_resource_version, binding_write_revision,
                      write_credential_purpose, write_credential_generation,
                      presign_credential_purpose, presign_credential_generation,
                      starting_inventory_generation, state, active_cache_slot,
                      expires_at, created_at)
                     VALUES
                       ('cache-single-pre', 1, 'single-pre', 1, 'single',
                        1, 1, 1, 1, 1, 1, 'write', 1, NULL, NULL, 1,
                        'observing', 1, 100, 1),
                       ('cache-single-post', 1, 'single-post', 1, 'single',
                        1, 1, 1, 1, 1, 1, 'write', 1, NULL, NULL, 1,
                        'active', 1, 100, 1),
                       ('cache-multipart-pre', 1, 'multipart-pre', 1, 'multipart',
                        1, 1, 1, 1, 1, 1, 'write', 1, NULL, NULL, 1,
                        'observing', 1, 100, 1),
                       ('cache-multipart-post', 1, 'multipart-post', 1, 'multipart',
                        1, 1, 1, 1, 1, 1, 'write', 1, NULL, NULL, 1,
                        'active', 1, 100, 1),
                       ('cache-presigned-pre', 1, 'presigned-pre', 1, 'presigned',
                        1, 1, 1, 1, 1, 1, 'write', 1, 'presign', 1, 1,
                        'observing', 1, 100, 1),
                       ('cache-presigned-post', 1, 'presigned-post', 1, 'presigned',
                        1, 1, 1, 1, 1, 1, 'write', 1, 'presign', 1, 1,
                        'active', 1, 100, 1)",
                    vec![],
                )
                .expecting(6),
            ])
            .await
    }

    /// Narrows the write-failure fixture to one quota-backed completing cache ticket.
    pub(crate) async fn prepare_ambiguous_recovery_test_tickets(&self) -> Result<()> {
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM cache_write_tickets
                     WHERE ticket_id <> 'cache-multipart-post'",
                    vec![],
                )
                .expecting(5),
                Statement::new(
                    "UPDATE cache_write_tickets SET expires_at = 1000000000",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE cache_write_tickets
                     SET state = 'completing', expires_at = 100,
                         quota_org_id = 1, quota_delta_bytes = 1,
                         quota_delta_objects = 1, quota_state = 'reserved'
                     WHERE ticket_id = 'cache-multipart-post'",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE org_usage
                     SET used_bytes = 1, object_count = 1, updated_at = 100
                     WHERE org_id = 1",
                    vec![],
                )
                .expecting(1),
            ])
            .await
    }

    /// Returns settlement-only cache ticket state for recovery tests.
    pub(crate) async fn test_cache_write_ticket_settlement(
        &self,
        ticket_id: &str,
    ) -> Result<TestWriteTicketSettlement> {
        let row = self
            .backend
            .query_opt(
                "SELECT state, quota_state, active_cache_slot,
                        covered_inventory_generation, recovery_attempts, finished_at
                 FROM cache_write_tickets WHERE ticket_id = ?1",
                &vals![ticket_id],
            )
            .await?
            .context("cache write ticket disappeared")?;
        Ok(TestWriteTicketSettlement {
            state: row.get(0)?,
            quota_state: row.get(1)?,
            active_slot: row.get(2)?,
            covered_inventory_generation: row.get(3)?,
            recovery_attempts: row.get(4)?,
            finished_at: row.get(5)?,
        })
    }

    /// Returns the quota counters represented by the recovery fixture reservations.
    pub(crate) async fn test_org_usage(&self, org_id: i64) -> Result<(i64, i64)> {
        let row = self
            .backend
            .query_opt(
                "SELECT used_bytes, object_count FROM org_usage WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?
            .context("organization usage disappeared")?;
        Ok((row.get(0)?, row.get(1)?))
    }

    /// Finds the cache ticket created for one injected request path.
    pub(crate) async fn test_cache_write_ticket_for_key(
        &self,
        object_key: &str,
    ) -> Result<Option<CacheWriteTicketRecord>> {
        self.backend
            .query_opt(
                "SELECT ticket_id, cache_id, object_key, declared_size, observed_final_size,
                        uploaded_size, upload_kind, placement_id, placement_resource_version,
                        placement_write_spec_version, binding_id,
                        binding_resource_version, binding_write_revision,
                        write_credential_purpose, write_credential_generation,
                        presign_credential_purpose, presign_credential_generation,
                        starting_inventory_generation, covered_inventory_generation,
                        backend_upload_id, state, expires_at, resource_version,
                        prior_object_size, prior_object_hash, prior_object_etag,
                        intended_object_hash
                 FROM cache_write_tickets WHERE cache_id = 1 AND object_key = ?1",
                &vals![object_key],
            )
            .await?
            .map(|row| row_to_cache_write_ticket(&row))
            .transpose()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::SurfaceTarget;

    #[tokio::test]
    async fn do_e2e_fixture_has_distinct_flat_and_nested_surface_identities() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_do_e2e_topology_fixture().await.unwrap();

        assert!(db
            .binary_cache_by_slug("flat-cache")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .binary_cache_by_slug("failure/cache")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .registry_by_slug("flat-registry")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .registry_by_slug("failure/registry")
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn multipart_retry_rejects_same_size_with_different_body_digest() {
        let existing = WriteTicketPartRecord {
            part_number: 1,
            admitted_size: 4,
            body_digest: "a".repeat(64),
            state: "confirmed".to_string(),
            etag: Some("etag".to_string()),
        };
        assert!(require_same_part_body(&existing, 4, &"b".repeat(64)).is_err());
        assert!(require_same_part_body(&existing, 4, &"a".repeat(64)).is_ok());
    }

    #[tokio::test]
    async fn reusable_cache_write_ticket_requires_exact_live_request_and_writer() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();

        let single = db
            .reusable_cache_write_ticket(
                1,
                "single-pre",
                1,
                "single",
                "observing",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(single.ticket_id, "cache-single-pre");
        assert!(db
            .reusable_cache_write_ticket(
                1,
                "single-pre",
                2,
                "single",
                "observing",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .is_none());
        assert!(db
            .reusable_cache_write_ticket(
                1,
                "single-pre",
                1,
                "single",
                "observing",
                None,
                1,
                1,
                1,
                1,
                100,
            )
            .await
            .unwrap()
            .is_none());

        db.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET intended_object_hash = ?1
                 WHERE ticket_id = 'cache-single-post'",
                vals!["a".repeat(64)],
            )
            .expecting(1)])
            .await
            .unwrap();
        let active_single = db
            .reusable_cache_write_ticket(
                1,
                "single-post",
                1,
                "single",
                "active",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active_single.ticket_id, "cache-single-post");

        let multipart_observing = db
            .reusable_cache_write_ticket(
                1,
                "multipart-pre",
                1,
                "multipart",
                "observing",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(multipart_observing.ticket_id, "cache-multipart-pre");

        db.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET backend_upload_id = 'backend-upload'
                 WHERE ticket_id = 'cache-multipart-post'",
                vec![],
            )
            .expecting(1)])
            .await
            .unwrap();
        let multipart = db
            .reusable_cache_write_ticket(
                1,
                "multipart-post",
                1,
                "multipart",
                "active",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(multipart.ticket_id, "cache-multipart-post");

        db.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET state = 'completing'
                 WHERE ticket_id = 'cache-multipart-post'",
                vec![],
            )
            .expecting(1)])
            .await
            .unwrap();
        let completing = db
            .reusable_cache_write_ticket(
                1,
                "multipart-post",
                1,
                "multipart",
                "completing",
                None,
                1,
                1,
                1,
                1,
                50,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completing.ticket_id, "cache-multipart-post");
    }

    #[tokio::test]
    async fn multipart_parts_admit_and_confirm_independently_under_concurrency() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET declared_size = 8
                 WHERE ticket_id = 'cache-multipart-post'",
                vec![],
            )
            .expecting(1)])
            .await
            .unwrap();

        let digest_one = "1".repeat(64);
        let digest_two = "2".repeat(64);
        let (cache_one, cache_two) = tokio::join!(
            db.admit_cache_write_part("cache-multipart-post", 1, 1, 4, &digest_one,),
            db.admit_cache_write_part("cache-multipart-post", 1, 2, 4, &digest_two,),
        );
        cache_one.unwrap();
        cache_two.unwrap();
        let (cache_one, cache_two) = tokio::join!(
            db.confirm_cache_write_part("cache-multipart-post", 1, 1, "etag-1"),
            db.confirm_cache_write_part("cache-multipart-post", 1, 2, "etag-2"),
        );
        cache_one.unwrap();
        cache_two.unwrap();
        let ticket = db
            .cache_write_ticket("cache-multipart-post")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ticket.uploaded_size, 8);
        db.confirm_cache_write_part("cache-multipart-post", 1, 1, "etag-1")
            .await
            .unwrap();
        assert!(db
            .confirm_cache_write_part("cache-multipart-post", 1, 1, "different-etag")
            .await
            .is_err());
        assert!(db
            .admit_cache_write_part("cache-multipart-post", 1, 3, 1, &"4".repeat(64),)
            .await
            .is_err());
        assert!(db
            .admit_cache_write_part("cache-multipart-post", 1, 1, 4, &"3".repeat(64),)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn simultaneous_same_part_admission_is_idempotent_or_conflicts_by_body() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET declared_size = 4
                 WHERE ticket_id = 'cache-multipart-post'",
                vec![],
            )
            .expecting(1)])
            .await
            .unwrap();
        let digest = "a".repeat(64);

        let (cache_left, cache_right) = tokio::join!(
            db.admit_cache_write_part("cache-multipart-post", 1, 1, 4, &digest),
            db.admit_cache_write_part("cache-multipart-post", 1, 1, 4, &digest),
        );
        cache_left.unwrap();
        cache_right.unwrap();
        let cache = db
            .cache_write_ticket("cache-multipart-post")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cache.uploaded_size, 4);

        let conflicting = Database::open_in_memory().await.unwrap();
        conflicting
            .install_write_failure_test_tickets()
            .await
            .unwrap();
        conflicting
            .backend
            .checked_batch(&[Statement::new(
                "UPDATE cache_write_tickets SET declared_size = 4
                 WHERE ticket_id = 'cache-multipart-post'",
                vec![],
            )
            .expecting(1)])
            .await
            .unwrap();
        let digest_left = "b".repeat(64);
        let digest_right = "c".repeat(64);
        let (cache_left, cache_right) = tokio::join!(
            conflicting.admit_cache_write_part("cache-multipart-post", 1, 1, 4, &digest_left,),
            conflicting.admit_cache_write_part("cache-multipart-post", 1, 1, 4, &digest_right,),
        );
        assert_eq!(
            usize::from(cache_left.is_ok()) + usize::from(cache_right.is_ok()),
            1
        );
        let cache = conflicting
            .cache_write_ticket("cache-multipart-post")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cache.uploaded_size, 4);
    }

    #[tokio::test]
    async fn uncertain_cache_writes_commit_quota_and_retain_inventory_fences() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.prepare_ambiguous_recovery_test_tickets().await.unwrap();

        let cache = db
            .cache_write_ticket("cache-multipart-post")
            .await
            .unwrap()
            .unwrap();
        db.mark_cache_write_ticket_uncertain(&cache.ticket_id, cache.resource_version, 20)
            .await
            .unwrap();
        let cache = db
            .test_cache_write_ticket_settlement(&cache.ticket_id)
            .await
            .unwrap();
        assert_eq!(cache.state, "completed");
        assert_eq!(cache.quota_state, "committed");
        assert_eq!(cache.active_slot, None);
        assert_eq!(cache.covered_inventory_generation, None);

        assert_eq!(db.test_org_usage(1).await.unwrap(), (1, 1));
    }

    #[tokio::test]
    async fn completing_ambiguity_becomes_conservative_after_bounded_retries() {
        let db = Database::open_in_memory().await.unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        db.prepare_ambiguous_recovery_test_tickets().await.unwrap();

        for attempt in 0..8 {
            let cache = db
                .cache_write_ticket("cache-multipart-post")
                .await
                .unwrap()
                .unwrap();
            db.defer_cache_write_recovery(
                &cache.ticket_id,
                cache.resource_version,
                200 + attempt,
                "opaque or delayed completion evidence",
            )
            .await
            .unwrap();
        }

        let cache = db
            .test_cache_write_ticket_settlement("cache-multipart-post")
            .await
            .unwrap();
        assert_eq!(cache.state, "completed");
        assert_eq!(cache.covered_inventory_generation, None);
        assert_eq!(cache.quota_state, "committed");
        assert_eq!(cache.active_slot, None);
        assert_eq!(cache.recovery_attempts, 8);
        assert_eq!(db.test_org_usage(1).await.unwrap(), (1, 1));
    }

    #[tokio::test]
    async fn cache_creation_initializes_fail_closed_gc_topology() {
        let db = Database::open_in_memory().await.unwrap();
        let cache_id = db
            .create_binary_cache(None, "new-cache", "New cache", "private", 40, "zstd", true)
            .await
            .unwrap();
        let state = db.cache_gc_topology_state(cache_id).await.unwrap().unwrap();
        assert_eq!(state.epoch, 0);
        assert_eq!(state.inventory_generation, 1);
        assert!(!state.destructive_enabled);
        let policy = db
            .cache_gc_policy_topology(cache_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.unreferenced_grace_secs, 604_800);
    }

    #[tokio::test]
    async fn expired_write_ticket_scans_require_bounded_pages() {
        let db = Database::open_in_memory().await.unwrap();
        assert!(db
            .list_expired_cache_write_tickets(1, 10, i64::MIN, "", 257)
            .await
            .is_err());
        assert!(db
            .list_expired_cache_write_tickets_global(10, i64::MIN, "", 257)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cache_write_recovery_cursor_is_durable_and_cas_guarded() {
        let db = Database::open_in_memory().await.unwrap();
        assert_eq!(
            db.cache_write_recovery_cursor().await.unwrap(),
            (
                crate::cache_scan::CACHE_WRITE_RECOVERY_CURSOR_START,
                String::new(),
                1
            )
        );

        db.advance_cache_write_recovery_cursor(1, 42, "ticket-42", 100)
            .await
            .unwrap();
        assert_eq!(
            db.cache_write_recovery_cursor().await.unwrap(),
            (42, "ticket-42".to_string(), 2)
        );

        assert!(db
            .advance_cache_write_recovery_cursor(1, 43, "stale-ticket", 101)
            .await
            .is_err());
        assert_eq!(
            db.cache_write_recovery_cursor().await.unwrap(),
            (42, "ticket-42".to_string(), 2)
        );
    }

    #[tokio::test]
    async fn quota_reservation_rolls_back_with_failed_ticket_batch() {
        let db = Database::open_in_memory().await.unwrap();
        db.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO orgs (id, stable_id, slug, name, created_at)
                     VALUES (1, 'org:00000000000000000000000000000001',
                       'quota-test', 'Quota test', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO org_quotas (org_id, max_bytes, max_objects)
                     VALUES (1, 100, 10)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
                     VALUES (1, 0, 0, 1)",
                    vec![],
                )
                .expecting(1),
            ])
            .await
            .unwrap();

        let mut statements = quota_reservation_statements(Some(1), 40, 1, 2);
        statements.push(
            Statement::new(
                "UPDATE org_usage SET updated_at = 2 WHERE org_id = 999",
                vec![],
            )
            .expecting(1),
        );
        assert!(db.backend.checked_batch(&statements).await.is_err());

        let usage = db
            .backend
            .query_opt(
                "SELECT used_bytes, object_count FROM org_usage WHERE org_id = 1",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.get::<i64>(0).unwrap(), 0);
        assert_eq!(usage.get::<i64>(1).unwrap(), 0);

        assert!(db
            .backend
            .checked_batch(&quota_reservation_statements(Some(1), 101, 1, 3))
            .await
            .is_err());
        let usage = db
            .backend
            .query_opt(
                "SELECT used_bytes, object_count FROM org_usage WHERE org_id = 1",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.get::<i64>(0).unwrap(), 0);
        assert_eq!(usage.get::<i64>(1).unwrap(), 0);
    }

    async fn gc_fixture() -> Database {
        let db = Database::open_in_memory().await.unwrap();
        db.backend
            .execute(
                "INSERT INTO authorization_scopes
                 (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                 VALUES ('cache:00000000000000000000000000000001', 'binary_cache',
                         NULL, 'instance', 'cache:00000000000000000000000000000001', 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO authorization_scope_ancestors
                 (descendant_scope_key, ancestor_scope_key, depth)
                 VALUES
                   ('cache:00000000000000000000000000000001',
                    'cache:00000000000000000000000000000001', 0),
                   ('cache:00000000000000000000000000000001', 'instance', 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO binary_caches
                 (id, stable_id, slug, name, visibility, created_at,
                  scope_key, owner_scope_key)
                 VALUES (1, 'cache:00000000000000000000000000000001',
                         'test/cache', 'Cache', 'private', 1,
                         'cache:00000000000000000000000000000001', 'instance')",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO cache_inventory_generations
                 (cache_id, generation, owner_token, lease_expires_at,
                  state, content_digest, published_at, created_at)
                 VALUES (1, 1, 'bootstrap', 2,
                   'published', 'inventory-1', 1, 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO cache_gc_policies
                 (cache_id, unreferenced_grace_secs, deletion_concurrency,
                  retry_initial_secs, retry_max_secs, retry_max_attempts,
                  tombstone_retention_secs)
                 VALUES (1, 3600, 2, 5, 300, 5, 86400)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO cache_gc_deletion_capacity (cache_id, running_count)
                 VALUES (1, 0)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO cache_gc_state
                 (cache_id, epoch, epoch_owner_token, inventory_generation)
                 VALUES (1, 0, 'bootstrap', 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO cache_gc_heads
                 (cache_id, resource_version, updated_at)
                 VALUES (1, 1, 1)",
                &[],
            )
            .await
            .unwrap();
        db
    }

    async fn install_inventory_placement(db: &Database) {
        db.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO bindings
                     (id, name, kind, is_instance_default, instance_default_key,
                      created_at, stable_id, owner_scope_key, local_root_path,
                      resource_version, updated_at)
                     VALUES (1, 'inventory-store', 'local_fs', 1, 'singleton',
                       1, 'inventory-store', 'instance', '/inventory', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_consumer_scopes
                     (binding_id, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     VALUES (1, 'instance', 1, 'owner', 'active', 'test', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, cache_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, binding_grant_state, prefix, kind,
                      desired_state, desired_read_enabled, write_spec_version,
                      requires_conditional_writes, created_at, updated_at)
                     VALUES (1, 1, 'primary', 1, 'instance', 1, 'active', '',
                       'complete', 'active', 1, 1, 1, 1, 1)",
                    vec![],
                )
                .expecting(1),
            ])
            .await
            .unwrap();
    }

    async fn stage_test_inventory_candidate(
        db: &Database,
        generation: i64,
        placement_id: i64,
        narinfo_hash: &str,
    ) {
        let owner_token = "inventory-owner";
        let text = "StorePath: /nix/store/abc123-demo-1.0\n\
                    URL: nar/demo.nar.zst\n\
                    Compression: zstd\n\
                    FileHash: file-demo\n\
                    FileSize: 20\n\
                    NarHash: nar-demo\n\
                    NarSize: 40\n";
        let parsed = crate::service::parse_cache_narinfo(1, "abc123", text, 20).unwrap();
        db.stage_cache_surface_object_identity(
            1,
            generation,
            placement_id,
            owner_token,
            "abc123.narinfo",
            narinfo_hash,
            i64::try_from(text.len()).unwrap(),
        )
        .await
        .unwrap();
        db.stage_cache_surface_object_identity(
            1,
            generation,
            placement_id,
            owner_token,
            &parsed.nar_url,
            &parsed.file_hash,
            parsed.file_size,
        )
        .await
        .unwrap();
        for (key, hash, size) in [
            (
                "abc123.narinfo",
                narinfo_hash,
                i64::try_from(text.len()).unwrap(),
            ),
            (
                parsed.nar_url.as_str(),
                parsed.file_hash.as_str(),
                parsed.file_size,
            ),
        ] {
            db.stage_cache_object_presence(
                owner_token,
                &CacheObjectPresenceObservation {
                    cache_id: 1,
                    object_key: key.to_string(),
                    placement_id,
                    state: "present".into(),
                    observed_hash: Some(hash.to_string()),
                    observed_size: Some(size),
                    etag: Some(format!("etag-{key}")),
                    inventory_generation: generation,
                    observed_at: 20,
                },
            )
            .await
            .unwrap();
        }
        db.stage_cache_inventory_narinfo_candidate(
            owner_token,
            &CacheInventoryNarinfoCandidate {
                cache_id: 1,
                generation,
                placement_id,
                store_hash: parsed.store_hash,
                store_name: parsed.store_name,
                identity_digest: "a".repeat(64),
                narinfo_object_key: "abc123.narinfo".into(),
                nar_object_key: parsed.nar_url,
                nar_hash: parsed.nar_hash,
                nar_size: parsed.nar_size,
                file_hash: parsed.file_hash,
                file_size: parsed.file_size,
                compression: parsed.compression,
                deriver: parsed.deriver,
                signature: parsed.signature,
                content_address: parsed.content_address,
                references: parsed.references,
                published_at: parsed.published_at,
            },
        )
        .await
        .unwrap();
        db.stage_cache_inventory_manifest(
            1,
            generation,
            placement_id,
            owner_token,
            &format!("placement-{placement_id}-digest"),
            2,
            20,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn inventory_publication_failure_leaks_no_objects_and_corrected_retry_succeeds() {
        let db = gc_fixture().await;
        install_inventory_placement(&db).await;
        let key = "abc123.narinfo";
        db.backend
            .execute(
                "INSERT INTO surface_objects
                 (cache_id, object_key, object_kind, partition_key, content_hash,
                  size, created_at, updated_at)
                 VALUES (1, ?1, 'immutable', ?2, 'old-identity', 1, 1, 1)",
                &vals![key, sha2::Sha256::digest(key.as_bytes()).to_vec()],
            )
            .await
            .unwrap();

        db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 10, 100)
            .await
            .unwrap();
        stage_test_inventory_candidate(&db, 2, 1, "new-identity").await;
        assert!(db
            .publish_cache_inventory_topology(
                1,
                2,
                "inventory-owner",
                "aggregate-digest",
                0,
                "inventory-conflict",
                20,
            )
            .await
            .is_err());

        let visible: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM surface_objects WHERE cache_id = 1",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(
            visible, 1,
            "failed publication must not materialize the staged NAR"
        );
        assert!(db
            .normalized_cache_object(1, "abc123")
            .await
            .unwrap()
            .is_none());

        db.fail_cache_inventory_topology(1, 2, "inventory-owner")
            .await
            .unwrap();
        let staged: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM cache_inventory_staged_surface_objects
                 WHERE cache_id = 1 AND generation = 2",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(staged, 0, "failure must cascade all generation staging");

        db.backend
            .execute(
                "DELETE FROM surface_objects WHERE cache_id = 1 AND object_key = ?1",
                &vals![key],
            )
            .await
            .unwrap();
        db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 30, 120)
            .await
            .unwrap();
        stage_test_inventory_candidate(&db, 2, 1, "new-identity").await;
        db.publish_cache_inventory_topology(
            1,
            2,
            "inventory-owner",
            "aggregate-digest-corrected",
            0,
            "inventory-corrected",
            40,
        )
        .await
        .unwrap();

        assert!(db
            .normalized_cache_object(1, "abc123")
            .await
            .unwrap()
            .is_some());
        let state = db.cache_gc_topology_state(1).await.unwrap().unwrap();
        assert_eq!(state.inventory_generation, 2);
        assert_eq!(state.object_graph_generation, 1);
    }

    #[tokio::test]
    async fn inventory_lease_fences_live_owner_and_recovers_abandoned_generation() {
        let db = gc_fixture().await;
        install_inventory_placement(&db).await;

        db.begin_cache_inventory_topology(1, 2, 0, "owner-a", 10, 20)
            .await
            .unwrap();
        db.stage_cache_surface_object_identity(
            1,
            2,
            1,
            "owner-a",
            "nar/a.nar.zst",
            &"a".repeat(64),
            1,
        )
        .await
        .unwrap();

        assert!(db
            .begin_cache_inventory_topology(1, 2, 0, "owner-b", 19, 30)
            .await
            .is_err());
        db.heartbeat_cache_inventory_topology(1, 2, "owner-a", 19, 29)
            .await
            .unwrap();
        assert!(db
            .heartbeat_cache_inventory_topology(1, 2, "owner-a", 19, 28)
            .await
            .is_err());
        assert!(db
            .begin_cache_inventory_topology(1, 2, 0, "owner-b", 28, 40)
            .await
            .is_err());
        db.stage_cache_inventory_manifest(1, 2, 1, "owner-a", "owner-a-manifest", 1, 28)
            .await
            .unwrap();
        assert!(db
            .publish_cache_inventory_topology(
                1,
                2,
                "owner-a",
                "expired-owner-publication",
                0,
                "expired-owner-mutation",
                29,
            )
            .await
            .is_err());

        db.begin_cache_inventory_topology(1, 2, 0, "owner-b", 29, 40)
            .await
            .unwrap();
        assert!(db
            .stage_cache_surface_object_identity(
                1,
                2,
                1,
                "owner-a",
                "nar/stale.nar.zst",
                &"b".repeat(64),
                1,
            )
            .await
            .is_err());
        assert!(db
            .cache_staged_surface_object_identity(1, 2, 1, "owner-b", "nar/a.nar.zst",)
            .await
            .unwrap()
            .is_none());

        db.fail_cache_inventory_topology(1, 2, "owner-a")
            .await
            .unwrap();
        db.heartbeat_cache_inventory_topology(1, 2, "owner-b", 30, 41)
            .await
            .unwrap();
        db.fail_cache_inventory_topology(1, 2, "owner-b")
            .await
            .unwrap();
        assert!(db
            .heartbeat_cache_inventory_topology(1, 2, "owner-b", 31, 42)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn inventory_publication_rejects_cross_placement_identity_drift() {
        let db = gc_fixture().await;
        install_inventory_placement(&db).await;
        db.backend
            .execute(
                "INSERT INTO surface_placements
                 (id, cache_id, name, binding_id, consumer_scope_key,
                  binding_grant_generation, binding_grant_state, prefix, kind,
                  desired_state, desired_read_enabled, write_spec_version,
                  requires_conditional_writes, created_at, updated_at)
                 VALUES (2, 1, 'replica', 1, 'instance', 1, 'active', 'replica/',
                   'complete', 'active', 1, 1, 1, 1, 1)",
                &[],
            )
            .await
            .unwrap();

        db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 10, 100)
            .await
            .unwrap();
        stage_test_inventory_candidate(&db, 2, 1, "first-identity").await;
        stage_test_inventory_candidate(&db, 2, 2, "second-identity").await;
        assert!(db
            .publish_cache_inventory_topology(
                1,
                2,
                "inventory-owner",
                "conflicting-placement-digest",
                0,
                "inventory-placement-conflict",
                20,
            )
            .await
            .is_err());
        assert!(db
            .normalized_cache_object(1, "abc123")
            .await
            .unwrap()
            .is_none());
        let visible: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM surface_objects WHERE cache_id = 1",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(
            visible, 0,
            "conflicting replica evidence must remain staged"
        );

        db.fail_cache_inventory_topology(1, 2, "inventory-owner")
            .await
            .unwrap();
        db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 30, 120)
            .await
            .unwrap();
        stage_test_inventory_candidate(&db, 2, 1, "corrected-identity").await;
        stage_test_inventory_candidate(&db, 2, 2, "corrected-identity").await;
        db.publish_cache_inventory_topology(
            1,
            2,
            "inventory-owner",
            "corrected-placement-digest",
            0,
            "inventory-placement-corrected",
            40,
        )
        .await
        .unwrap();

        assert!(db
            .normalized_cache_object(1, "abc123")
            .await
            .unwrap()
            .is_some());
        let placements: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*)
                 FROM object_placements placement
                 JOIN surface_objects object
                   ON object.id = placement.surface_object_id
                  AND object.cache_id = placement.cache_id
                 WHERE placement.cache_id = 1
                   AND object.object_key = 'abc123.narinfo'
                   AND placement.state = 'present'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(placements, 2);
    }

    #[tokio::test]
    async fn inventory_stages_explicit_missing_for_new_cross_placement_objects() {
        let db = gc_fixture().await;
        install_inventory_placement(&db).await;
        db.backend
            .execute(
                "INSERT INTO surface_placements
                 (id, cache_id, name, binding_id, consumer_scope_key,
                  binding_grant_generation, binding_grant_state, prefix, kind,
                  desired_state, desired_read_enabled, write_spec_version,
                  requires_conditional_writes, created_at, updated_at)
                 VALUES (2, 1, 'shard', 1, 'instance', 1, 'active', 'shard/',
                   'complete', 'active', 1, 1, 1, 1, 1)",
                &[],
            )
            .await
            .unwrap();
        db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 10, 100)
            .await
            .unwrap();
        db.stage_cache_surface_object_identity(
            1,
            2,
            1,
            "inventory-owner",
            "nar/only-on-primary.nar.zst",
            &"a".repeat(64),
            20,
        )
        .await
        .unwrap();
        db.stage_cache_object_presence(
            "inventory-owner",
            &CacheObjectPresenceObservation {
                cache_id: 1,
                object_key: "nar/only-on-primary.nar.zst".into(),
                placement_id: 1,
                state: "present".into(),
                observed_hash: Some("a".repeat(64)),
                observed_size: Some(20),
                etag: Some("primary-etag".into()),
                inventory_generation: 2,
                observed_at: 10,
            },
        )
        .await
        .unwrap();

        db.stage_missing_cache_inventory_observations(1, 2, 2, "inventory-owner", 11)
            .await
            .unwrap();
        let missing: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM cache_inventory_object_observations
                 WHERE cache_id = 1 AND generation = 2 AND placement_id = 2
                   AND object_key = 'nar/only-on-primary.nar.zst'
                   AND state = 'missing'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(missing, 1);
        assert!(db
            .surface_object_named(SurfaceTarget::BinaryCache(1), "nar/only-on-primary.nar.zst",)
            .await
            .unwrap()
            .is_none());
    }

    async fn deletion_fixture() -> Database {
        let db = gc_fixture().await;
        db.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO bindings
                     (id, name, kind, is_instance_default, instance_default_key,
                      created_at, stable_id, owner_scope_key, local_root_path,
                      resource_version, updated_at)
                     VALUES (1, 'delete-store', 'local_fs', 1, 'singleton',
                       1, 'instance-default', 'instance', '/delete-store', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_credential_revisions
                     (binding_id, purpose, generation, secret_version_ref,
                      validation_state, validated_at, credential_fingerprint,
                      created_by, created_at)
                     VALUES (1, 'delete', 1, 'test-delete-secret', 'valid', 1,
                       'test-delete-fingerprint', 'test', 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO binding_consumer_scopes
                     (binding_id, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     VALUES (1, 'instance', 1, 'owner', 'active', 'test', 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, cache_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, binding_grant_state, prefix, kind,
                      desired_state, desired_read_enabled, write_spec_version,
                      requires_conditional_writes, created_at, updated_at)
                     VALUES (1, 1, 'primary', 1, 'instance', 1, 'active', '',
                       'complete', 'active', 1, 1, 1, 1, 1)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO surface_objects
                     (id, cache_id, object_key, object_kind, partition_key,
                      content_hash, size, lifecycle_state, tombstoned_at,
                      created_at, updated_at)
                     VALUES (1, 1, 'nar/object.nar', 'immutable', zeroblob(32),
                       'sha256-object', 12, 'tombstoned', 10, 1, 10)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO object_placements
                     (surface_object_id, cache_id, placement_id, state,
                      observed_hash, observed_size, etag,
                      observed_inventory_generation, observed_at)
                     VALUES (1, 1, 1, 'deleting', 'sha256-object', 12,
                       'etag-1', 1, 10)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO topology_operations
                     (operation_id, operation_kind, authorization_scope_key,
                      control_permission, primary_target_kind, primary_target_stable_id,
                      state, progress_total, created_at)
                     VALUES ('gc-operation', 'cache_gc', 'instance',
                       'cache.gc.execute', 'binary_cache',
                       'cache:00000000000000000000000000000001',
                       'pending', 1, 10)",
                    vec![],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO object_deletion_jobs
                     (job_id, cache_id, originating_operation_id,
                      operation_target_kind, operation_target_stable_id,
                      surface_object_id, placement_id, phase, expected_etag,
                      expected_hash, expected_size, expected_inventory_generation,
                      binding_id, binding_resource_version,
                      delete_credential_generation,
                      state, active_slot, max_attempts, next_attempt_at, created_at)
                     VALUES ('delete-job', 1, 'gc-operation', 'binary_cache',
                       'cache:00000000000000000000000000000001', 1, 1, 'nar',
                       'etag-1', 'sha256-object', 12, 1, 1, 1, 1,
                       'pending', 1, 3, 10, 10)",
                    vec![],
                )
                .expecting(1),
            ])
            .await
            .unwrap();
        db
    }

    #[tokio::test]
    async fn deletion_receipt_recovers_response_before_job_finalization() {
        let db = deletion_fixture().await;
        let claimed = db
            .claim_cache_gc_deletion_job(1, "delete-job", 1, "delete-request", 20)
            .await
            .unwrap();
        assert_eq!(claimed.state, "running");
        let response = RecordObjectDeletionAttemptResponse {
            request_id: "delete-request".into(),
            cache_id: 1,
            job_id: "delete-job".into(),
            outcome: "deleted".into(),
            response_etag: Some("etag-1".into()),
            response_hash: Some("sha256-object".into()),
            response_size: Some(12),
            error_class: None,
            response_detail: None,
            responded_at: 21,
        };
        let receipt = db
            .record_object_deletion_attempt_response(&response)
            .await
            .unwrap();
        assert_eq!(receipt.state, "responded");
        assert_eq!(
            db.record_object_deletion_attempt_response(&response)
                .await
                .unwrap(),
            receipt
        );

        let recovered = db
            .current_object_deletion_attempt_receipt(1, "delete-job")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.outcome.as_deref(), Some("deleted"));
        let succeeded = db
            .succeed_cache_gc_deletion_job(
                1,
                "delete-job",
                claimed.resource_version,
                "delete-request",
                22,
            )
            .await
            .unwrap();
        assert_eq!(succeeded.state, "succeeded");
        assert_eq!(succeeded.confirmed_reclaimed_bytes, 12);
        assert_eq!(
            db.object_deletion_attempt_receipt("delete-request")
                .await
                .unwrap()
                .unwrap()
                .state,
            "finalized"
        );
        assert_eq!(
            db.succeed_cache_gc_deletion_job(
                1,
                "delete-job",
                claimed.resource_version,
                "delete-request",
                22,
            )
            .await
            .unwrap()
            .state,
            "succeeded"
        );
    }

    #[tokio::test]
    async fn stale_root_epoch_rolls_back_the_entire_batch() {
        let db = gc_fixture().await;
        db.create_manual_retention_root_topology(&CreateManualRetentionRoot {
            root_id: "root-1".into(),
            reason_id: "reason-1".into(),
            cache_id: 1,
            store_hash: "abc123".into(),
            reason: "release operator pin".into(),
            actor: "user:1".into(),
            actor_kind: "user".into(),
            actor_id: 1,
            lease_id: None,
            lease_expires_at: None,
            expected_epoch: 0,
            mutation_id: "mutation-1".into(),
            now: 100,
        })
        .await
        .unwrap();
        let root = db
            .manual_retention_root(1, "root-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(root.id, "root-1");
        assert_eq!(root.reason, "release operator pin");

        let stale = db
            .create_manual_retention_root_topology(&CreateManualRetentionRoot {
                root_id: "root-stale".into(),
                reason_id: "reason-stale".into(),
                cache_id: 1,
                store_hash: "def456".into(),
                reason: "must roll back".into(),
                actor: "user:1".into(),
                actor_kind: "user".into(),
                actor_id: 1,
                lease_id: None,
                lease_expires_at: None,
                expected_epoch: 0,
                mutation_id: "mutation-stale".into(),
                now: 101,
            })
            .await;
        assert!(stale.is_err());
        assert!(db
            .manual_retention_root(1, "root-stale")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            db.cache_gc_topology_state(1).await.unwrap().unwrap().epoch,
            1
        );
    }

    #[tokio::test]
    async fn renewal_and_revocation_preserve_history_but_remove_active_reason() {
        let db = gc_fixture().await;
        db.create_manual_retention_root_topology(&CreateManualRetentionRoot {
            root_id: "root-lease".into(),
            reason_id: "reason-lease-1".into(),
            cache_id: 1,
            store_hash: "abc123".into(),
            reason: "temporary investigation".into(),
            actor: "user:1".into(),
            actor_kind: "user".into(),
            actor_id: 1,
            lease_id: Some("lease-1".into()),
            lease_expires_at: Some(200),
            expected_epoch: 0,
            mutation_id: "mutation-1".into(),
            now: 100,
        })
        .await
        .unwrap();
        assert_eq!(db.active_cache_root_reasons(1, 150).await.unwrap().len(), 1);

        db.renew_retention_lease_topology(&RenewRetentionLease {
            root_id: "root-lease".into(),
            lease_id: "lease-2".into(),
            reason_id: "reason-lease-2".into(),
            cache_id: 1,
            expected_root_version: 1,
            expires_at: 300,
            actor: "user:2".into(),
            expected_epoch: 1,
            mutation_id: "mutation-2".into(),
            now: 160,
        })
        .await
        .unwrap();
        assert_eq!(
            db.retention_lease("lease-1").await.unwrap().unwrap().state,
            "superseded"
        );
        assert_eq!(db.active_cache_root_reasons(1, 250).await.unwrap().len(), 1);

        db.revoke_retention_lease_topology(1, "lease-2", 2, 2, "mutation-3", "user:2", 170)
            .await
            .unwrap();
        assert_eq!(
            db.retention_lease("lease-2").await.unwrap().unwrap().state,
            "revoked"
        );
        assert!(db
            .active_cache_root_reasons(1, 171)
            .await
            .unwrap()
            .is_empty());
        let historical: i64 = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM retention_leases
                 WHERE manual_retention_root_id = 'root-lease'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(historical, 2);
    }

    #[tokio::test]
    async fn incomplete_closure_cannot_publish_or_change_the_mark_head() {
        let db = gc_fixture().await;
        db.create_manual_retention_root_topology(&CreateManualRetentionRoot {
            root_id: "missing-root".into(),
            reason_id: "missing-root-reason".into(),
            cache_id: 1,
            store_hash: "missing123".into(),
            reason: "prove fail closed".into(),
            actor: "user:1".into(),
            actor_kind: "user".into(),
            actor_id: 1,
            lease_id: None,
            lease_expires_at: None,
            expected_epoch: 0,
            mutation_id: "root-mutation".into(),
            now: 100,
        })
        .await
        .unwrap();
        db.begin_cache_gc_generation(&BeginCacheGcGeneration {
            generation_id: "generation-incomplete".into(),
            cache_id: 1,
            cutoff_at: 110,
            expected_epoch: 1,
            created_at: 110,
        })
        .await
        .unwrap();

        assert!(db
            .complete_cache_gc_generation(1, "generation-incomplete", 111)
            .await
            .is_err());
        let state = db.cache_gc_topology_state(1).await.unwrap().unwrap();
        assert_eq!(state.current_mark_generation_id, None);
        let generation_state: String = db
            .backend
            .query_opt(
                "SELECT state FROM cache_gc_generations
                 WHERE generation_id = 'generation-incomplete'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(generation_state, "building");

        db.stage_cache_gc_coverage_error(
            1,
            "generation-incomplete",
            &CacheGcCoverageError {
                error_id: "coverage-missing-root".into(),
                kind: "missing_root".into(),
                store_hash: Some("missing123".into()),
                referenced_store_hash: None,
                detail: "the root has no complete cache object".into(),
            },
        )
        .await
        .unwrap();
        db.fail_cache_gc_generation(
            1,
            "generation-incomplete",
            "closure coverage is incomplete",
            112,
        )
        .await
        .unwrap();
        assert_eq!(
            db.cache_gc_topology_state(1)
                .await
                .unwrap()
                .unwrap()
                .current_mark_generation_id,
            None
        );
    }

    #[tokio::test]
    async fn placement_change_cannot_cross_a_mark_generation() {
        let db = gc_fixture().await;
        db.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO bindings
                     (id, name, kind, is_instance_default, instance_default_key,
                      created_at, stable_id, owner_scope_key, local_root_path)
                     VALUES (10, 'objects', 'local_fs', 1, 'singleton', 1,
                       'instance-default', 'instance', '/objects')",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO binding_consumer_scopes
                     (binding_id, consumer_scope_key, grant_generation,
                      grant_kind, state, granted_by, granted_at, resource_version)
                     VALUES (10, 'instance', 1, 'owner', 'active', 'test', 1, 1)",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO surface_placements
                     (id, cache_id, name, binding_id, consumer_scope_key,
                      binding_grant_generation, binding_grant_state, prefix, kind,
                      desired_state, created_at, updated_at)
                     VALUES (11, 1, 'primary', 10, 'instance', 1, 'active',
                       'cache/', 'complete', 'active', 1, 1)",
                    vec![],
                ),
            ])
            .await
            .unwrap();
        db.begin_cache_gc_generation(&BeginCacheGcGeneration {
            generation_id: "placement-snapshot".into(),
            cache_id: 1,
            cutoff_at: 10,
            expected_epoch: 0,
            created_at: 10,
        })
        .await
        .unwrap();
        db.backend
            .execute(
                "UPDATE surface_placements
                 SET desired_state = 'offline', resource_version = 2,
                     updated_at = 11
                 WHERE id = 11",
                &[],
            )
            .await
            .unwrap();

        assert!(db
            .complete_cache_gc_generation(1, "placement-snapshot", 12)
            .await
            .is_err());
        let state: String = db
            .backend
            .query_opt(
                "SELECT state FROM cache_gc_generations
                 WHERE generation_id = 'placement-snapshot'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(state, "building");
    }

    #[tokio::test]
    async fn disabling_a_subscription_preserves_its_removal_grace() {
        let db = gc_fixture().await;
        db.backend
            .execute(
                "INSERT INTO authorization_scopes
                 (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                 VALUES ('registry:00000000000000000000000000000007', 'registry',
                         NULL, 'instance', 'registry:00000000000000000000000000000007', 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO authorization_scope_ancestors
                 (descendant_scope_key, ancestor_scope_key, depth)
                 VALUES
                   ('registry:00000000000000000000000000000007',
                    'registry:00000000000000000000000000000007', 0),
                   ('registry:00000000000000000000000000000007', 'instance', 1)",
                &[],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO registries
                 (id, stable_id, slug, created_at, scope_key, owner_scope_key)
                 VALUES (7, 'registry:00000000000000000000000000000007', 'source', 1,
                         'registry:00000000000000000000000000000007', 'instance')",
                &[],
            )
            .await
            .unwrap();
        let selector_json = "{}".to_string();
        let selector_digest = digest_text(&selector_json);
        let subscription = db
            .set_cache_retention_subscription_topology(&SetCacheRetentionSubscriptionTopology {
                cache_id: 1,
                registry_id: 7,
                selector_json: selector_json.clone(),
                selector_digest: selector_digest.clone(),
                removal_grace_secs: 100,
                exposure_acknowledged_at: None,
                enabled: true,
                expected_resource_version: None,
                expected_cache_epoch: 0,
                mutation_id: "subscription-create".into(),
                now: 10,
            })
            .await
            .unwrap();
        db.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO cache_retention_refreshes
                     (refresh_id, subscription_id, cache_id, registry_id,
                      expected_subscription_version, expected_cache_epoch,
                      selector_digest, registry_source_revision,
                      registry_index_generation, registry_index_digest, state,
                      started_at, activated_at, parent_grace_until, finished_at,
                      expected_reason_count, actual_reason_count)
                     VALUES ('refresh-1', ?1, 1, 7, 1, 1, ?2, 'commit-1',
                       1, 'index-digest-1',
                       'complete', 20, 20, 120, 20, 1, 1)",
                    vals![subscription.id, selector_digest],
                ),
                Statement::new(
                    "INSERT INTO cache_retention_refresh_heads
                     (subscription_id, cache_id, registry_id,
                      current_refresh_id, resource_version, updated_at)
                     VALUES (?1, 1, 7, 'refresh-1', 1, 20)",
                    vals![subscription.id],
                ),
                Statement::new(
                    "INSERT INTO cache_root_reasons
                     (id, cache_id, registry_id, store_hash, reason_key,
                      source_kind, refresh_id, retention_subscription_id,
                      source_ref, source_revision, refreshed_at)
                     VALUES ('registry-reason', 1, 7, 'abc123', 'catalog:abc123',
                       'registry_catalog', 'refresh-1', ?1,
                       'catalog:abc123', 'commit-1', 20)",
                    vals![subscription.id],
                ),
            ])
            .await
            .unwrap();

        db.set_cache_retention_subscription_topology(&SetCacheRetentionSubscriptionTopology {
            cache_id: 1,
            registry_id: 7,
            selector_json,
            selector_digest,
            removal_grace_secs: 100,
            exposure_acknowledged_at: None,
            enabled: false,
            expected_resource_version: Some(1),
            expected_cache_epoch: 1,
            mutation_id: "subscription-disable".into(),
            now: 200,
        })
        .await
        .unwrap();
        assert_eq!(db.active_cache_root_reasons(1, 250).await.unwrap().len(), 1);
        assert!(db
            .active_cache_root_reasons(1, 300)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn tombstone_reap_preserves_unresolved_edges_for_possible_reactivation() {
        let db = gc_fixture().await;
        db.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO surface_objects
                     (id, cache_id, object_key, object_kind, partition_key,
                      content_hash, size, lifecycle_state, tombstoned_at,
                      created_at, updated_at)
                     VALUES
                       (101, 1, 'abc123.narinfo', 'immutable',
                        X'0000000000000000000000000000000000000000000000000000000000000000',
                        'narinfo-a', 10, 'tombstoned', 100, 1, 100),
                       (102, 1, 'nar/a', 'immutable',
                        X'0101010101010101010101010101010101010101010101010101010101010101',
                        'file-a', 20, 'tombstoned', 100, 1, 100),
                       (103, 1, 'def456.narinfo', 'immutable',
                        X'0202020202020202020202020202020202020202020202020202020202020202',
                        'narinfo-b', 11, 'tombstoned', 100, 1, 100),
                       (104, 1, 'nar/b', 'immutable',
                        X'0303030303030303030303030303030303030303030303030303030303030303',
                        'file-b', 21, 'tombstoned', 100, 1, 100)",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO cache_nar_objects
                     (cache_id, nar_surface_object_id, nar_hash, nar_size,
                      file_hash, file_size, compression)
                     VALUES (1, 102, 'nar-a', 40, 'file-a', 20, 'zstd'),
                            (1, 104, 'nar-b', 41, 'file-b', 21, 'zstd')",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO cache_objects
                     (id, cache_id, store_hash, store_name,
                      narinfo_surface_object_id, nar_surface_object_id,
                      nar_hash, nar_size, file_hash, file_size, compression,
                      reference_count, lifecycle_state, published_at,
                      tombstoned_at)
                     VALUES
                       (201, 1, 'abc123', 'a', 101, 102, 'nar-a', 40,
                        'file-a', 20, 'zstd', 0, 'tombstoned', 1, 100),
                       (202, 1, 'def456', 'b', 103, 104, 'nar-b', 41,
                        'file-b', 21, 'zstd', 1, 'tombstoned', 1, 100)",
                    vec![],
                ),
                Statement::new(
                    "INSERT INTO cache_object_references
                     (cache_id, cache_object_id, referenced_store_hash,
                      referenced_cache_object_id)
                     VALUES (1, 202, 'abc123', 201)",
                    vec![],
                ),
            ])
            .await
            .unwrap();

        db.reap_cache_object_tombstone(1, 201, 1, 0, "reap-a", 86_500)
            .await
            .unwrap();

        assert!(db
            .backend
            .query_opt("SELECT 1 FROM cache_objects WHERE id = 201", &[])
            .await
            .unwrap()
            .is_none());
        let edge = db
            .backend
            .query_opt(
                "SELECT referenced_store_hash, referenced_cache_object_id
                 FROM cache_object_references
                 WHERE cache_id = 1 AND cache_object_id = 202",
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edge.get::<String>(0).unwrap(), "abc123");
        assert_eq!(edge.get::<Option<i64>>(1).unwrap(), None);
    }
}
