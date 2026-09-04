//! Transactional OCI retention planning and physical-deletion evidence.
//!
//! A GC run freezes the registry root set, retention policy, provider-enumerated
//! inventories, and every placement/binding capability before any logical
//! object becomes invisible. Applying the reviewed plan tombstones all
//! candidates atomically. Provider workers then consume exact placement
//! actions and return conditional-delete evidence; catalog and quota identity
//! is removed only after every frozen placement confirms absence.

use aos_oci_types::{MediaType, RepositoryName, Sha256Digest};

mod inventory;
mod inventory_model;
mod plan;
mod plan_frontier;
mod plan_model;
mod purge_plan;
mod read;
mod remediation;
mod repair_worker;
mod worker;

#[cfg(test)]
mod tests;

pub use inventory::*;
pub use plan::*;
pub use purge_plan::*;
pub use remediation::*;
pub use repair_worker::*;
pub use worker::*;

/// Maximum records returned by one GC read-model page.
pub const OCI_GC_MAX_PAGE_SIZE: u32 = 250;

/// Maximum candidate graph size accepted by one plan.
pub const OCI_GC_MAX_OBJECTS: usize = 2_000;

/// Maximum candidates materialized by one synchronous reviewed plan.
pub const OCI_GC_MAX_CANDIDATES: usize = 100;

/// Maximum descriptor/referrer edges traversed by one plan.
pub const OCI_GC_MAX_EDGES: usize = 4_096;

/// Maximum physical placement actions materialized by one synchronous plan.
pub const OCI_GC_MAX_ACTIONS: usize = 500;

/// Maximum placement snapshots accepted by one synchronous plan.
pub const OCI_GC_MAX_PLACEMENTS: usize = 32;

/// Maximum traversal depth accepted by one plan.
pub const OCI_GC_MAX_DEPTH: usize = 64;

/// Maximum age of a completed provider inventory used for a new plan.
pub const OCI_GC_MAX_INVENTORY_AGE_SECONDS: i64 = 15 * 60;

/// Age after which a nonterminal upload/publication is operationally stuck.
pub const OCI_OPERATIONS_STUCK_SECONDS: i64 = 15 * 60;

/// Review lifetime of one unapplied plan.
pub const OCI_GC_PLAN_TTL_SECONDS: i64 = 15 * 60;

/// Maximum provider inventory entries accepted per append call.
pub const OCI_GC_INVENTORY_BATCH_SIZE: usize = 500;

/// Maximum canonical keys accepted by one synchronous provider inventory.
pub const OCI_GC_MAX_INVENTORY_OBJECTS: usize = 2_000;

/// Maximum aggregate UTF-8 key bytes accepted by one provider inventory.
pub const OCI_GC_MAX_INVENTORY_KEY_BYTES: usize = 1_048_576;

/// One cursor-bound page from the OCI GC read model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcPage<T> {
    /// Records in deterministic keyset order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page, or `None` at the end.
    pub next_cursor: Option<String>,
    /// Registry mutation epoch frozen by the run.
    pub captured_mutation_epoch: i64,
}

/// Durable reviewed OCI garbage-collection run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcGenerationRecord {
    /// Stable run and operation identity.
    pub id: String,
    /// Registry owning the run.
    pub registry_id: i64,
    /// Authenticated actor that created and may apply the plan.
    pub actor_id: String,
    /// `planned`, `applying`, `complete`, `aborted`, or `failed`.
    pub state: String,
    /// Registry mutation epoch frozen during planning.
    pub captured_mutation_epoch: i64,
    /// Epoch after atomic tombstoning, when applied.
    pub applied_mutation_epoch: Option<i64>,
    /// Stored policy version, or zero for effective defaults.
    pub policy_resource_version: i64,
    /// Canonical retention policy digest.
    pub policy_digest: Sha256Digest,
    /// Canonical hard-root identity digest.
    pub root_set_digest: Sha256Digest,
    /// Canonical digest of every exact placement inventory.
    pub placement_inventory_digest: Sha256Digest,
    /// Canonical placement/binding/capability digest.
    pub topology_digest: Sha256Digest,
    /// Canonical reviewed plan digest.
    pub plan_digest: Sha256Digest,
    /// Actor-bound review confirmation hash.
    pub confirmation_hash: Sha256Digest,
    /// Provider keys across all exact frozen placement inventories.
    pub inventory_object_count: u64,
    /// Provider bytes across all exact frozen placement inventories.
    pub inventory_byte_size: u64,
    /// Registry-global immutable objects reached from the reviewed root set.
    pub reachable_object_count: u64,
    /// Bytes eligible for deletion.
    pub planned_bytes: u64,
    /// Registry-global immutable objects eligible for deletion.
    pub planned_objects: u64,
    /// Candidates whose catalog/quota identity has been finalized.
    pub deleted_object_count: u64,
    /// Candidate bytes whose catalog/quota identity has been finalized.
    pub deleted_byte_size: u64,
    /// Exact physical placement actions in the plan.
    pub placement_action_count: u64,
    /// Review expiry in Unix seconds.
    pub expires_at: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Atomic tombstone time, when applied.
    pub applied_at: Option<i64>,
    /// Terminal time, when complete, aborted, or failed.
    pub finished_at: Option<i64>,
    /// Sanitized terminal failure detail.
    pub last_error: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One durable reason a plan failed closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcBlockerRecord {
    /// Owning run id.
    pub generation_id: String,
    /// Stable blocker classification.
    pub kind: String,
    /// Exact affected digest, when object-specific.
    pub digest: Option<Sha256Digest>,
    /// Bounded operator-facing detail.
    pub detail: String,
}

/// One registry-global immutable object selected for deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcCandidateRecord {
    /// Owning run id.
    pub generation_id: String,
    /// Exact immutable digest.
    pub digest: Sha256Digest,
    /// Persisted media type.
    pub media_type: MediaType,
    /// Exact compressed byte length.
    pub byte_size: u64,
    /// Canonical provider object key.
    pub object_key: String,
    /// Repositories linked before tombstoning.
    pub repositories: Vec<RepositoryName>,
    /// Conservative grace deadline derived from durable `unreferenced_since`.
    ///
    /// A NULL legacy observation remains ineligible until bounded authoritative
    /// reconciliation stamps it; the planner never infers an earlier deadline.
    pub eligible_at: i64,
    /// `planned`, `deleting`, `physically_absent`, `complete`, or `failed`.
    pub state: String,
    /// Logical catalog finalization time.
    pub finalized_at: Option<i64>,
    /// Sanitized terminal failure detail.
    pub last_error: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One physical placement action in a reviewed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcPlacementActionRecord {
    /// Stable action id.
    pub id: String,
    /// Owning run id.
    pub generation_id: String,
    /// Registry owning the immutable object.
    pub registry_id: i64,
    /// Exact immutable digest.
    pub digest: Sha256Digest,
    /// Canonical provider key frozen by the plan.
    pub object_key: String,
    /// Exact expected provider content hash.
    pub expected_hash: Sha256Digest,
    /// Exact expected provider byte length.
    pub expected_size: u64,
    /// Strong entity tag frozen by provider enumeration, when present.
    pub expected_strong_etag: Option<String>,
    /// Whether the sealed inventory contained the canonical key.
    pub inventory_entry_present: bool,
    /// Exact provider inventory generation used by the plan.
    pub inventory_generation_id: String,
    /// Canonical digest of the complete frozen provider inventory.
    pub inventory_digest: Sha256Digest,
    /// Provider enumeration observation time in Unix seconds.
    pub inventory_observed_at: i64,
    /// Frozen placement id.
    pub placement_id: i64,
    /// Frozen placement name.
    pub placement_name: String,
    /// Frozen provider prefix.
    pub placement_prefix: String,
    /// Frozen placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Frozen placement writer-spec version.
    pub placement_write_spec_version: i64,
    /// Frozen ready/complete observation version.
    pub placement_observation_version: i64,
    /// Frozen binding id.
    pub binding_id: i64,
    /// Frozen binding optimistic-concurrency version.
    pub binding_resource_version: i64,
    /// Frozen immutable binding writer revision.
    pub binding_write_revision: i64,
    /// Frozen delete credential purpose, absent for local filesystem IO.
    pub delete_credential_purpose: Option<String>,
    /// Frozen delete credential generation, absent for local filesystem IO.
    pub delete_credential_generation: Option<i64>,
    /// Frozen observed conditional-delete semantics.
    pub delete_capability_fingerprint: String,
    /// Frozen capability audit version.
    pub delete_capability_resource_version: i64,
    /// `pending`, `claimed`, `confirmed_absent`, or `failed`.
    pub state: String,
    /// Number of provider attempts.
    pub attempt_count: u32,
    /// Maximum provider attempts.
    pub max_attempts: u32,
    /// Earliest retry time in Unix seconds.
    pub next_attempt_at: i64,
    /// Sanitized latest failure detail.
    pub last_error: Option<String>,
    /// Absence-confirmation time.
    pub confirmed_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Current blockers that must be zero before registry identity deletion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciRegistryPurgeBlockers {
    /// OCI repositories, including empty metadata identities.
    pub repositories: u64,
    /// Remaining OCI blob catalog rows.
    pub catalog_objects: u64,
    /// Active upload/publication/lease rows.
    pub active_sessions: u64,
    /// Nonterminal GC runs or actions.
    pub gc_work: u64,
    /// Current provider-inventory keys still present and catalog-tracked.
    pub tracked_provider_objects: u64,
    /// Current provider-inventory keys with no catalog identity.
    pub untracked_provider_objects: u64,
    /// Placements missing an exact current complete inventory head.
    pub stale_or_missing_inventories: u64,
    /// Native snapshot references still owned by the registry.
    pub snapshot_references: u64,
}

/// Bounded aggregate counters for operational OCI GC metrics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciGcMetrics {
    /// Reviewed plans waiting for apply.
    pub planned_runs: u64,
    /// Runs with tombstoned candidates and physical work outstanding.
    pub applying_runs: u64,
    /// Successfully completed runs retained as audit history.
    pub completed_runs: u64,
    /// Terminal failed or aborted runs.
    pub failed_runs: u64,
    /// Bytes reviewed by currently planned or applying runs.
    pub planned_bytes: u64,
    /// Bytes whose candidates reached logical finalization.
    pub finalized_bytes: u64,
    /// Placement actions currently in the failed state.
    pub failed_actions: u64,
    /// Durable blockers on currently planned runs.
    pub blockers: u64,
    /// Placements missing a current-epoch complete provider inventory.
    pub stale_inventories: u64,
}

/// Global low-cardinality OCI storage and recovery metrics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciOperationsMetrics {
    /// Repository-link count, including reuse across repositories.
    pub catalog_logical_objects: u64,
    /// Repository-link bytes, including reused object bytes per link.
    pub catalog_logical_bytes: u64,
    /// Distinct catalog objects referenced by at least one repository.
    pub catalog_unique_objects: u64,
    /// Distinct bytes referenced by at least one repository.
    pub catalog_unique_bytes: u64,
    /// Objects in current complete provider inventory heads.
    pub provider_inventory_objects: u64,
    /// Bytes in current complete provider inventory heads.
    pub provider_inventory_bytes: u64,
    /// Active upload sessions.
    pub uploads_active: u64,
    /// Uploads executing completion.
    pub uploads_completing: u64,
    /// Completed upload sessions retained for recovery/audit.
    pub uploads_complete: u64,
    /// Failed upload sessions.
    pub uploads_failed: u64,
    /// Cancelled upload sessions.
    pub uploads_cancelled: u64,
    /// Expired active or completing uploads.
    pub uploads_expired_nonterminal: u64,
    /// Preparing publication sessions.
    pub publications_preparing: u64,
    /// Committing publication sessions.
    pub publications_committing: u64,
    /// Ready publication sessions.
    pub publications_ready: u64,
    /// Aborted publication sessions.
    pub publications_aborted: u64,
    /// Failed publication sessions.
    pub publications_failed: u64,
    /// Nonterminal publications older than the named stuck threshold.
    pub publications_stuck_nonterminal: u64,
    /// Total creation-to-commit seconds for ready publications.
    pub publication_ready_latency_seconds_sum: u64,
    /// Ready publications contributing to the latency sum.
    pub publication_ready_latency_count: u64,
    /// Registry placements ready/complete with a current inventory head.
    pub placements_ready: u64,
    /// Registry placements lacking health or a current inventory head.
    pub placements_unhealthy: u64,
    /// Age in seconds of the oldest current complete inventory head.
    pub max_inventory_age_seconds: u64,
    /// Failed provider inventory generations retained for recovery.
    pub failed_inventory_generations: u64,
    /// Expired provider inventory leases taken over by another receipt.
    pub inventory_takeover_count: u64,
    /// Operator maintenance requeues of exhausted GC actions.
    pub gc_requeue_count: u64,
    /// Current-head entries whose durable observed hash conflicts with identity.
    pub digest_mismatches: u64,
}

/// Result of one bounded crash-recovery finalization sweep.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciGcFinalizationSweep {
    /// Candidates promoted after every placement proved absent.
    pub finalized_candidates: u64,
    /// Runs whose catalog/quota identity was atomically removed.
    pub finalized_generations: u64,
}

impl OciRegistryPurgeBlockers {
    /// Returns whether any logical or physical deletion blocker remains.
    #[must_use]
    pub fn any(&self) -> bool {
        self.repositories != 0
            || self.catalog_objects != 0
            || self.active_sessions != 0
            || self.gc_work != 0
            || self.tracked_provider_objects != 0
            || self.untracked_provider_objects != 0
            || self.stale_or_missing_inventories != 0
            || self.snapshot_references != 0
    }
}
