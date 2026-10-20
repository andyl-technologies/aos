//! Topology records returned by typed Hub persistence operations.

use super::*;

/// A binding (system-of-record row): a named backend an org's
/// surfaces use through explicit physical placements.
#[derive(Debug, Clone, Default)]
pub struct BindingRecord {
    /// Database id.
    pub id: i64,
    /// Owning org id, or `None` for the instance-level default binding
    /// ([`is_instance_default`](Self::is_instance_default)).
    pub org_id: Option<i64>,
    /// Binding name, unique within the org.
    pub name: String,
    /// Backend kind: `local_fs` (a native host directory), `s3`/`r2` (an
    /// externally configured S3-compatible store), or the instance-owned
    /// Worker `deployment_r2` singleton. Organization rows only use `s3`/`r2`.
    pub kind: String,
    /// Whether this is the singleton instance-level default binding.
    /// Exactly one row carries this; it has a `None` `org_id`.
    pub is_instance_default: bool,
    /// Stable API identity, independent of database ids and display names.
    pub stable_id: String,
    /// Canonical owner scope (`instance` or `org:<id>`).
    pub owner_scope_key: String,
    /// Canonical local-filesystem root for a local binding.
    pub local_root_path: Option<String>,
    /// Object-store bucket for an S3-compatible binding.
    pub object_bucket: Option<String>,
    /// Binding-owned prefix within the object-store bucket.
    pub object_prefix: Option<String>,
    /// Canonical endpoint scheme.
    pub endpoint_scheme: Option<String>,
    /// Endpoint host representation (`dns`, `ipv4`, or `ipv6`).
    pub endpoint_host_kind: Option<String>,
    /// Canonical endpoint host bytes.
    pub endpoint_host_bytes: Option<Vec<u8>>,
    /// Explicit endpoint port.
    pub endpoint_port: Option<i64>,
    /// Object-store request-signing region.
    pub signing_region: Option<String>,
    /// Canonical access mode for the binding.
    pub access_mode: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Unix time the binding was created.
    pub created_at: i64,
    /// Unix time the desired binding spec last changed.
    pub updated_at: i64,
}

/// A storage-binding row safe to expose to principals with read-only access.
///
/// This projection deliberately cannot represent provider coordinates,
/// credentials, or credential-version references. Queries returning it select
/// only these columns at the SQL boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingReadDetail {
    /// Database identity used only for same-request joins.
    pub id: i64,
    /// Owning organization, or `None` for the instance default.
    pub org_id: Option<i64>,
    /// Human-readable binding name.
    pub name: String,
    /// Provider kind without its connection coordinates.
    pub kind: String,
    /// Whether this is the instance-owned singleton.
    pub is_instance_default: bool,
    /// Stable API identity.
    pub stable_id: String,
    /// Canonical owner authorization scope.
    pub owner_scope_key: String,
    /// Optimistic concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last desired-spec update time in Unix seconds.
    pub updated_at: i64,
}

/// A compact storage-binding identity safe for read-only inventory pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingReadSummary {
    /// Database identity used only for same-request joins.
    pub id: i64,
    /// Owning organization, or `None` for the instance default.
    pub org_id: Option<i64>,
    /// Human-readable binding name.
    pub name: String,
    /// Provider kind without its connection coordinates.
    pub kind: String,
    /// Whether this is the instance-owned singleton.
    pub is_instance_default: bool,
    /// Stable API identity.
    pub stable_id: String,
}

/// One immutable credential-version reference attached to a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCredentialRevisionRecord {
    /// Owning binding.
    pub binding_id: i64,
    /// Capability purpose (`read`, `write`, `delete`, `list`, or `presign`).
    pub purpose: String,
    /// Monotonic purpose-local generation.
    pub generation: i64,
    /// Opaque immutable secret-manager version reference.
    pub secret_version_ref: String,
    /// Controller validation state.
    pub validation_state: String,
    /// Terminal validation time.
    pub validated_at: Option<i64>,
    /// Validation failure detail.
    pub validation_error: Option<String>,
    /// Server-owned semantic fingerprint.
    pub credential_fingerprint: String,
    /// Actor that created the revision.
    pub created_by: String,
    /// Creation time.
    pub created_at: i64,
    /// Resource version of the current-generation head.
    pub head_resource_version: i64,
}

/// A verified hostname whose paths may be mapped to Hub surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    /// Database id.
    pub id: i64,
    /// Owning organization, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Lowercase hostname without a scheme or path.
    pub hostname: String,
    /// Configured DNS provider identifier, when Hub-managed.
    pub desired_dns_provider: Option<String>,
    /// DNS lifecycle state.
    pub observed_dns_state: String,
    /// Configured TLS provider identifier, when Hub-managed.
    pub desired_tls_provider: Option<String>,
    /// TLS lifecycle state.
    pub observed_tls_state: String,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
    /// Verification time, or `None` while unverified.
    pub verified_at: Option<i64>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Per-placement progress toward publishing one registry generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationPlacementRecord {
    /// Publication being materialized.
    pub publication_id: String,
    /// Registry repeated to enforce same-registry composite references.
    pub registry_id: i64,
    /// Destination registry placement.
    pub placement_id: i64,
    /// Whether failure prevents the publication becoming current.
    pub required: bool,
    /// `preparing`, `writing_pointers`, `ready`, `failed`, or `retired`.
    pub state: String,
    /// Last observed transition time in Unix seconds.
    pub observed_at: i64,
}

/// Desired per-placement publication progress update.
#[derive(Debug, Clone)]
pub struct SetRegistryPublicationPlacement {
    /// Publication being materialized.
    pub publication_id: String,
    /// Destination registry placement.
    pub placement_id: i64,
    /// Whether this placement gates publication readiness.
    pub required: bool,
    /// Publication progress state.
    pub state: String,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// One physical placement of a registry or binary-cache surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfacePlacementRecord {
    /// Database id.
    pub id: i64,
    /// Registry target, or `None` for a binary-cache placement.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry placement.
    pub cache_id: Option<i64>,
    /// Stable human-readable name within the surface.
    pub name: String,
    /// Binding containing the placement.
    pub binding_id: i64,
    /// Surface-relative prefix within the binding.
    pub prefix: String,
    /// Derived placement role: observed authority is `primary`; otherwise the
    /// placement is a `replica`, `shard`, or `archive` according to its kind.
    pub derived_role: String,
    /// Latest observed operational state, defaulting to `provisioning` before observation.
    pub state: String,
    /// Inventory completeness: `complete`, `partial`, or `unknown`.
    pub completeness: String,
    /// Inclusive start of the half-open shard range.
    pub hash_range_start: Option<i64>,
    /// Exclusive end of the half-open shard range.
    pub hash_range_end: Option<i64>,
    /// Last completely published mutable-pointer publication.
    pub mutable_publication_id: Option<String>,
    /// Whether desired lifecycle and read configuration permit selection.
    pub effective_read_enabled: bool,
    /// Whether the complete desired/observed authority and capability tuple is effective.
    pub effective_write_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Desired placement shape: `complete`, `shard`, or `archive`.
    pub kind: String,
    /// Desired lifecycle: `active`, `draining`, or `offline`.
    pub desired_state: String,
    /// Desired read-selection switch before request-specific eligibility.
    pub desired_read_enabled: bool,
    /// Version of the placement's writer-critical topology.
    pub write_spec_version: i64,
    /// Whether this write contract requires conditional object writes.
    pub requires_conditional_writes: bool,
    /// Time of the latest controller observation, if any.
    pub observed_at: Option<i64>,
    /// Optimistic version of the controller observation, if any.
    pub observation_version: Option<i64>,
    /// Optimistic version of the registry publication watermark resource.
    pub watermark_resource_version: Option<i64>,
    /// Publication whose pointer advance currently owns the watermark CAS.
    pub watermark_pending_publication_id: Option<String>,
    /// Surface write-authority resource, if this surface has one.
    pub write_authority_id: Option<i64>,
    /// Placement currently requested as writer.
    pub authority_desired_placement_id: Option<i64>,
    /// Placement confirmed as writer by reconciliation.
    pub authority_observed_placement_id: Option<i64>,
    /// Placement write-spec version requested by authority.
    pub authority_desired_write_spec_version: Option<i64>,
    /// Placement write-spec version confirmed by reconciliation.
    pub authority_observed_write_spec_version: Option<i64>,
    /// Immutable binding-write revision requested by authority.
    pub authority_desired_binding_write_revision: Option<i64>,
    /// Immutable binding-write revision confirmed by reconciliation.
    pub authority_observed_binding_write_revision: Option<i64>,
    /// Requested authority generation.
    pub authority_desired_generation: Option<i64>,
    /// Confirmed authority generation.
    pub authority_observed_generation: Option<i64>,
    /// Authority reconciliation state, if authority exists.
    pub authority_reconciliation_state: Option<String>,
}

/// Stable classification for caller-correctable placement-create failures.
///
/// Errors without this marker are infrastructure failures and must remain
/// internal. This avoids interpreting backend-specific SQL error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfacePlacementCreateFailureKind {
    /// A request field violates the placement contract.
    InvalidArgument,
    /// The surface already has the requested stable placement name.
    AlreadyExists,
    /// Another placement owns a mutually exclusive topology resource.
    Conflict,
}

/// Typed placement-create failure preserved through `anyhow` context chains.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SurfacePlacementCreateFailure {
    pub(in crate::db) kind: SurfacePlacementCreateFailureKind,
    pub(in crate::db) message: String,
}

/// Caller-correctable write-authority mutation failure.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SurfaceWriteAuthorityMutationFailure {
    pub(in crate::db) message: String,
}

/// References that constrain a placement drain or metadata deletion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SurfacePlacementBlockers {
    /// A direct route selects the placement.
    pub direct_route: bool,
    /// A route selects a policy containing the placement.
    pub routed_policy: bool,
    /// A placement-selection policy contains the placement.
    pub policy_member: bool,
    /// Object-presence inventory exists for the placement.
    pub object_presence: bool,
    /// Registry-publication progress exists for the placement.
    pub publication: bool,
    /// Active registry-publication progress exists for the placement.
    pub active_publication: bool,
    /// Object-deletion jobs refer to the placement.
    pub deletion_job: bool,
    /// A topology operation refers to the placement.
    pub topology_operation: bool,
}

/// Creation-time topology defaults for the instance or one organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyDefaultsRecord {
    /// Database id.
    pub id: i64,
    /// Scope discriminator: `instance` or `organization`.
    pub scope_kind: String,
    /// Organization id for an organization-scoped row.
    pub org_id: Option<i64>,
    /// Stable uniqueness key (`instance` or `org:<id>`).
    pub scope_key: String,
    /// Default binding for new placements.
    pub binding_id: Option<i64>,
    /// Default domain for new routes.
    pub domain_id: Option<i64>,
    /// Default gateway for new direct routes.
    pub gateway_id: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
}

/// Final stable-identity topology defaults projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableTopologyDefaultsRecord {
    /// Canonical owner scope.
    pub scope_key: String,
    /// Default storage-binding stable id.
    pub binding_id: Option<String>,
    /// Default domain stable id.
    pub domain_id: Option<String>,
    /// Default endpoint stable id.
    pub endpoint_id: Option<String>,
    /// Pinned endpoint generation.
    pub endpoint_generation: Option<i64>,
    /// Default gateway stable id.
    pub gateway_id: Option<String>,
    /// Pinned gateway generation.
    pub gateway_generation: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One logical object owned by a registry or binary-cache surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceObjectRecord {
    /// Database id.
    pub id: i64,
    /// Registry target, or `None` for a binary-cache object.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry object.
    pub cache_id: Option<i64>,
    /// Surface-relative object key.
    pub object_key: String,
    /// Content digest, when known.
    pub content_hash: Option<String>,
    /// Object size in bytes, when known.
    pub size: Option<i64>,
    /// Object kind: `immutable` or `mutable_pointer`.
    pub object_kind: String,
    /// Authoritative publication owning a mutable pointer.
    pub mutable_publication_id: Option<String>,
    /// Logical lifecycle: `active` or `tombstoned`.
    pub lifecycle_state: String,
    /// Tombstone time, or `None` while active.
    pub tombstoned_at: Option<i64>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last update time in Unix seconds.
    pub updated_at: i64,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One observed copy of a logical object at a named placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPresenceRecord {
    /// Surface-relative logical object key.
    pub object_ref: String,
    /// Stable placement name within the surface.
    pub placement_name: String,
    /// `present`, `copying`, `missing`, `corrupt`, or `deleting`.
    pub state: String,
    /// Observed content digest, when known.
    pub content_digest: Option<String>,
    /// Observed byte size, when known.
    pub size: Option<i64>,
    /// Controller observation time in Unix seconds.
    pub observed_at: i64,
}

/// Byte evidence produced by one complete physical-placement scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementScanPresence {
    /// Logical surface object receiving the observation.
    pub surface_object_id: i64,
    /// `present`, `missing`, or `corrupt`.
    pub state: String,
    /// SHA-256 digest derived from the physical bytes, when present.
    pub observed_hash: Option<String>,
    /// Size derived from the physical bytes, when present.
    pub observed_size: Option<i64>,
    /// Backend-issued strong entity tag, when available.
    pub etag: Option<String>,
}

/// Earlier byte-verified evidence eligible for strong-version scan reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusablePlacementEvidence {
    /// Logical surface object described by the evidence.
    pub surface_object_id: i64,
    /// Presence state recorded by the prior publication or complete scan.
    pub state: String,
    /// SHA-256 digest verified for that provider version.
    pub observed_hash: Option<String>,
    /// Verified representation size.
    pub observed_size: Option<i64>,
    /// Provider-issued strong version identifier.
    pub etag: Option<String>,
}

/// Operator-confirmed equivalence between two exact surface placements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementEquivalenceRecord {
    /// Stable opaque equivalence identity.
    pub id: String,
    /// Owning registry or cache surface.
    pub surface: SurfaceTarget,
    /// First stable placement name.
    pub placement_a: String,
    /// Second stable placement name.
    pub placement_b: String,
    /// Digest of the reviewed validation evidence.
    pub evidence_digest: String,
    /// `active` while the equivalence exists.
    pub state: String,
    /// Exact creation-plan token for apply replay.
    pub creation_token: String,
    /// Confirmation time in Unix seconds.
    pub confirmed_at: i64,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// A typed reference to either kind of servable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceTarget {
    /// A registry surface by database id.
    Registry(i64),
    /// A managed binary-cache surface by database id.
    BinaryCache(i64),
}

/// Consistency contract applied when selecting placements for one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementReadRequirement<'a> {
    /// Reads a registry pointer key only from a placement at the current publication.
    RegistryCurrentPublication(&'a str),
    /// Reads an immutable object, using exact presence when it is inventoried.
    ImmutableObject(&'a str),
    /// Reads an object that has no publication or per-object consistency contract.
    Untracked,
}

/// One atomic snapshot of configured placements and its readable candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementReadPlan {
    /// Whether the surface has any placement rows, including ineligible ones.
    pub has_configured_placements: bool,
    /// Whether configured shard placements require an explicit delivery policy.
    pub has_policy_only_shards: bool,
    /// Consistency-eligible candidates in deterministic read order.
    pub candidates: Vec<SurfacePlacementRecord>,
    /// Whether a miss contradicts authoritative logical object inventory.
    pub miss_is_inconsistent: bool,
}

/// Input for creating a domain resource.
#[derive(Debug, Clone)]
pub struct NewDomain {
    /// Owning organization, or `None` for instance scope.
    pub org_id: Option<i64>,
    /// Hostname without scheme, port, path, query, or fragment.
    pub hostname: String,
    /// Optional DNS provider identifier.
    pub desired_dns_provider: Option<String>,
    /// Optional TLS provider identifier.
    pub desired_tls_provider: Option<String>,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
}

/// Input for a version-checked domain lifecycle update.
#[derive(Debug, Clone)]
pub struct UpdateDomain {
    /// Expected optimistic-concurrency version.
    pub expected_version: i64,
    /// Optional DNS provider identifier.
    pub desired_dns_provider: Option<String>,
    /// Optional TLS provider identifier.
    pub desired_tls_provider: Option<String>,
    /// Serialized external-access-provider declaration.
    pub access_provider_json: String,
}

/// Desired specification for creating a physical surface placement.
#[derive(Debug, Clone)]
pub struct NewSurfacePlacementSpec {
    /// Surface receiving the placement.
    pub surface: SurfaceTarget,
    /// Stable human-readable name within the surface.
    pub name: String,
    /// Binding containing the placement.
    pub binding_id: i64,
    /// Surface-relative prefix within the binding.
    pub prefix: String,
    /// Placement shape: `complete`, `shard`, or `archive`.
    pub kind: String,
    /// Desired lifecycle: `active` or `offline` at creation time.
    pub desired_state: String,
    /// Typed half-open shard range, required only for `shard`.
    pub hash_range: Option<SurfacePlacementHashRange>,
    /// Whether reads may select the placement.
    pub desired_read_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
    /// Whether the placement's writer contract requires conditional writes.
    pub requires_conditional_writes: bool,
}

/// Typed half-open range in the fixed 16-bit shard-key space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfacePlacementHashRange {
    /// Inclusive range start.
    pub start: i64,
    /// Exclusive range end, at most 65536.
    pub end: i64,
}

/// Desired fields for a version-checked placement update.
#[derive(Debug, Clone)]
pub struct UpdateSurfacePlacementSpec {
    /// Expected optimistic-concurrency version.
    pub expected_version: i64,
    /// New desired lifecycle state.
    pub desired_state: String,
    /// Whether desired read selection may use the placement.
    pub desired_read_enabled: bool,
    /// Lower ordinal is preferred for reads.
    pub read_order: i64,
}

/// One immutable snapshot of a binding's write contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingWriteRevisionRecord {
    /// Binding whose credentials and capabilities were snapshotted.
    pub binding_id: i64,
    /// Monotonically increasing binding-local revision.
    pub revision: i64,
    /// Credential purpose pinned by the revision.
    pub write_credential_purpose: String,
    /// Credential generation pinned by the revision, if topology-managed.
    pub write_credential_generation: i64,
    /// Opaque reference to one immutable credential version.
    pub write_credential_version_ref: String,
    /// Whether ordinary object writes are supported.
    pub writes_supported: bool,
    /// Whether conditional object writes are supported.
    pub conditional_writes_supported: bool,
    /// Fingerprint of the entire immutable revision.
    pub revision_fingerprint: String,
    /// Fingerprint of capability semantics, independent of credential identity.
    pub capability_fingerprint: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
}

/// Desired immutable storage-binding write revision.
#[derive(Debug, Clone)]
pub struct NewBindingWriteRevision {
    /// Binding receiving the revision.
    pub binding_id: i64,
    /// Exact validated write-credential generation.
    pub write_credential_generation: i64,
    /// Whether ordinary object writes are supported.
    pub writes_supported: bool,
    /// Whether conditional object writes are supported.
    pub conditional_writes_supported: bool,
    /// Fingerprint of the entire immutable revision.
    pub revision_fingerprint: String,
    /// Fingerprint of capability semantics, independent of credential identity.
    pub capability_fingerprint: String,
}

/// Desired default binding-write revision for new placement plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingWriteStateRecord {
    /// Binding owning the pointer.
    pub binding_id: i64,
    /// Validated revision selected for new plans, if configured.
    pub current_write_revision: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Last pointer update time in Unix seconds.
    pub updated_at: i64,
}

/// Controller validation of one immutable binding-write revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingWriteObservationRecord {
    /// Binding owning the revision.
    pub binding_id: i64,
    /// Validated immutable revision.
    pub revision: i64,
    /// `unknown`, `validating`, `valid`, or `invalid`.
    pub state: String,
    /// Validation completion time for terminal states.
    pub validated_at: Option<i64>,
    /// Failure detail for an invalid revision.
    pub error: Option<String>,
    /// Monotonic observation version.
    pub observation_version: i64,
}

/// Desired and observed single-writer authority for one surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceWriteAuthorityRecord {
    /// Database id.
    pub id: i64,
    /// Immutable globally unique identity for this authority lifetime.
    pub incarnation_id: String,
    /// Registry target, or `None` for a binary cache.
    pub registry_id: Option<i64>,
    /// Binary-cache target, or `None` for a registry.
    pub cache_id: Option<i64>,
    /// Authority mode; currently always `single_writer`.
    pub mode: String,
    /// Placement requested as writer.
    pub desired_placement_id: i64,
    /// Requested placement write-spec version.
    pub desired_write_spec_version: i64,
    /// Requested immutable binding-write revision.
    pub desired_binding_write_revision: i64,
    /// Requested reconciliation generation.
    pub desired_generation: i64,
    /// Placement confirmed as writer, if reconciliation has succeeded before.
    pub observed_placement_id: Option<i64>,
    /// Confirmed placement write-spec version.
    pub observed_write_spec_version: Option<i64>,
    /// Confirmed immutable binding-write revision.
    pub observed_binding_write_revision: Option<i64>,
    /// Confirmed reconciliation generation.
    pub observed_generation: Option<i64>,
    /// `pending`, `ready`, or `failed`.
    pub reconciliation_state: String,
    /// Reconciliation failure detail.
    pub reconciliation_error: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last desired or observed transition time in Unix seconds.
    pub updated_at: i64,
}

/// Scope receiving creation-time topology defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyScope {
    /// Instance scope.
    Instance,
    /// Organization scope by database id.
    Organization(i64),
}

/// Input for setting creation-time topology defaults.
#[derive(Debug, Clone)]
pub struct SetTopologyDefaults {
    /// Scope receiving the defaults.
    pub scope: TopologyScope,
    /// Default binding for new placements.
    pub binding_id: Option<i64>,
    /// Default domain for new routes.
    pub domain_id: Option<i64>,
    /// Default gateway for new direct routes.
    pub gateway_id: Option<i64>,
    /// Expected version, or `None` when creating the row.
    pub expected_version: Option<i64>,
}

/// Input for creating or updating a logical surface object.
#[derive(Debug, Clone)]
pub struct SetSurfaceObject {
    /// Owning surface.
    pub surface: SurfaceTarget,
    /// Surface-relative object key.
    pub object_key: String,
    /// Content digest, when known.
    pub content_hash: Option<String>,
    /// Object size in bytes, when known.
    pub size: Option<i64>,
    /// `immutable` or `mutable_pointer`.
    pub object_kind: String,
    /// Authoritative registry publication for a mutable pointer.
    pub mutable_publication_id: Option<String>,
}

/// An immutable semantic plan awaiting an explicit apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPlanRecord {
    /// Stable opaque plan id.
    pub plan_id: String,
    /// Operation family that produced the plan.
    pub plan_kind: String,
    /// Actor kind captured at planning time.
    pub actor_kind: String,
    /// Actor database id, when applicable.
    pub actor_id: Option<i64>,
    /// Human-readable actor label.
    pub actor_label: String,
    /// Authorization scope.
    pub scope: String,
    /// Serialized input resource versions.
    pub input_versions_json: String,
    /// Serialized semantic effects.
    pub effects_json: String,
    /// Serialized warnings.
    pub warnings_json: String,
    /// Hash of a required confirmation token.
    pub confirmation_hash: Option<String>,
    /// Caller key making plan creation replay-safe.
    pub request_idempotency_key: Option<String>,
    /// Digest of the exact semantic planning input bound to that key.
    pub request_digest: Option<String>,
    /// Caller key that successfully applied the plan.
    pub apply_idempotency_key: Option<String>,
    /// Canonical serialized apply response used for successful replay.
    pub apply_result_json: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Expiry time in Unix seconds.
    pub expires_at: i64,
    /// Apply time, or `None` while unused.
    pub applied_at: Option<i64>,
}

/// Input for storing an immutable semantic plan.
#[derive(Debug, Clone)]
pub struct NewTopologyPlan {
    /// Stable opaque plan id.
    pub plan_id: String,
    /// Operation family that produced the plan.
    pub plan_kind: String,
    /// Actor kind captured at planning time.
    pub actor_kind: String,
    /// Actor database id, when applicable.
    pub actor_id: Option<i64>,
    /// Human-readable actor label.
    pub actor_label: String,
    /// Authorization scope.
    pub scope: String,
    /// Serialized input resource versions.
    pub input_versions_json: String,
    /// Serialized semantic effects.
    pub effects_json: String,
    /// Serialized warnings.
    pub warnings_json: String,
    /// Hash of a required confirmation token.
    pub confirmation_hash: Option<String>,
    /// Caller-supplied key making plan creation replay-safe.
    pub request_idempotency_key: Option<String>,
    /// Expiry time in Unix seconds.
    pub expires_at: i64,
}

/// A durable long-running topology operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyOperationRecord {
    /// Stable opaque operation id.
    pub operation_id: String,
    /// Operation family.
    pub operation_kind: String,
    /// Immutable authorization scope resolved from all targets at creation.
    pub authorization_scope_key: String,
    /// Exact closed permission required to control the operation.
    pub control_permission: String,
    /// Closed kind of the immutable primary target snapshot.
    pub primary_target_kind: String,
    /// Stable public identity of the primary target.
    pub primary_target_stable_id: String,
    /// Exact immutable generation of the primary target, or zero.
    pub primary_target_generation_key: i64,
    /// Exact configuration digest of the primary target, or empty.
    pub primary_target_configuration_digest: String,
    /// Lifecycle state.
    pub state: String,
    /// Completed work units.
    pub progress_current: i64,
    /// Total work units, when known.
    pub progress_total: Option<i64>,
    /// Serialized operation-specific status.
    pub detail_json: String,
    /// Failure detail.
    pub error: Option<String>,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Start time in Unix seconds.
    pub started_at: Option<i64>,
    /// Finish time in Unix seconds.
    pub finished_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// One keyset-paginated operation inventory page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyOperationPage {
    /// Operations in newest-first deterministic order.
    pub records: Vec<TopologyOperationRecord>,
    /// Exclusive operation-id cursor for the next page.
    pub next_cursor: Option<String>,
}

/// One immutable typed target snapshot attached to an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyOperationTargetRecord {
    /// Owning operation.
    pub operation_id: String,
    /// Semantic target role within the operation.
    pub role: String,
    /// Closed resource kind.
    pub target_kind: String,
    /// Stable public resource identity, retained after resource deletion.
    pub stable_id: String,
    /// Stable authorization scope captured when the operation was created.
    pub authorization_scope_key: String,
    /// Exact permission required to control this target.
    pub control_permission: aos_hub_model::domain::Permission,
    /// Exact immutable generation, or zero for stable resources.
    pub generation_key: i64,
    /// Exact configuration digest, or empty when the target has no such digest.
    pub configuration_digest: String,
}

/// A strongly typed live resource reference used only while creating an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewTopologyOperationTargetRef {
    /// Registry database identity.
    Registry(i64),
    /// Binary-cache database identity.
    BinaryCache(i64),
    /// Placement database identity.
    Placement(i64),
    /// Delivery-domain stable identity.
    Domain(String),
    /// Network-boundary stable identity.
    NetworkPolicy(String),
    /// Delivery-endpoint stable identity.
    Endpoint(String),
    /// Storage-gateway stable identity.
    Gateway(String),
    /// Delivery-route stable identity.
    Route(String),
    /// Storage-binding database identity.
    Binding(i64),
}

/// One target requested for a new durable operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTopologyOperationTarget {
    /// Closed semantic role.
    pub role: String,
    /// Strongly typed live resource reference.
    pub target: NewTopologyOperationTargetRef,
    /// Exact immutable generation, or zero for stable resources.
    pub generation_key: i64,
    /// Exact configuration digest, or empty when not applicable.
    pub configuration_digest: String,
}

/// Input for creating a durable topology operation.
#[derive(Debug, Clone)]
pub struct NewTopologyOperation {
    /// Stable opaque operation id.
    pub operation_id: String,
    /// Operation family.
    pub operation_kind: String,
    /// Exact permission required for later cancel and retry requests.
    pub control_permission: Permission,
    /// Non-empty immutable target snapshot with exactly one primary target.
    pub targets: Vec<NewTopologyOperationTarget>,
    /// Serialized operation-specific status.
    pub detail_json: String,
    /// Total work units, when known.
    pub progress_total: Option<i64>,
}

/// One immutable topology event awaiting audit and webhook materialization.
#[derive(Debug, Clone)]
pub struct TopologyEventOutboxRecord {
    /// Stable event identity used to deduplicate every derived record.
    pub event_id: String,
    /// Stable dotted event name exposed to audit and webhook consumers.
    pub event_name: String,
    /// Authorization scope that owns the changed resource.
    pub owner_scope_key: String,
    /// Organization receiving webhook deliveries, when the scope is tenant-owned.
    pub org_id: Option<i64>,
    /// Stable resource-kind vocabulary.
    pub resource_kind: String,
    /// Stable identity of the changed resource.
    pub resource_stable_id: String,
    /// Exact generation or revision changed by the transition.
    pub resource_generation_key: i64,
    /// Audit actor kind.
    pub actor_kind: String,
    /// Optional numeric actor identity.
    pub actor_id: Option<i64>,
    /// Human-readable audit actor label.
    pub actor_label: String,
    /// Canonical JSON event payload.
    pub payload_json: String,
    /// Unix time at which the domain transition committed.
    pub occurred_at: i64,
}

/// Input for a topology event inserted in the domain mutation transaction.
#[derive(Debug, Clone)]
pub struct NewTopologyEvent<'a> {
    /// Stable event identity.
    pub event_id: &'a str,
    /// Stable dotted event name.
    pub event_name: &'a str,
    /// Owning authorization scope.
    pub owner_scope_key: &'a str,
    /// Stable resource kind.
    pub resource_kind: &'a str,
    /// Stable resource identity.
    pub resource_stable_id: &'a str,
    /// Exact generation or revision.
    pub resource_generation_key: i64,
    /// Audit actor kind.
    pub actor_kind: &'a str,
    /// Optional numeric actor identity.
    pub actor_id: Option<i64>,
    /// Human-readable actor label.
    pub actor_label: &'a str,
    /// Canonical JSON event payload.
    pub payload_json: &'a str,
    /// Unix time of the transition.
    pub occurred_at: i64,
}

impl From<&BindingRecord> for BindingReadSummary {
    fn from(binding: &BindingRecord) -> Self {
        Self {
            id: binding.id,
            org_id: binding.org_id,
            name: binding.name.clone(),
            kind: binding.kind.clone(),
            is_instance_default: binding.is_instance_default,
            stable_id: binding.stable_id.clone(),
        }
    }
}

impl SurfacePlacementCreateFailure {
    /// Returns the stable public classification.
    #[must_use]
    pub fn kind(&self) -> SurfacePlacementCreateFailureKind {
        self.kind
    }

    /// Returns the stable, backend-independent public message.
    #[must_use]
    pub fn public_message(&self) -> &str {
        &self.message
    }

    /// Builds a classified failure without backend error detail.
    pub(in crate::db) fn new(
        kind: SurfacePlacementCreateFailureKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl SurfaceWriteAuthorityMutationFailure {
    /// Returns the stable, backend-independent public message.
    #[must_use]
    pub fn public_message(&self) -> &str {
        &self.message
    }

    pub(in crate::db) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl SurfacePlacementBlockers {
    /// Returns whether a serving route currently pins the placement.
    #[must_use]
    pub fn route_pinned(self) -> bool {
        self.direct_route || self.routed_policy
    }

    /// Returns whether any reference prevents metadata deletion.
    #[must_use]
    pub fn prevents_deletion(self) -> bool {
        self.direct_route
            || self.routed_policy
            || self.policy_member
            || self.object_presence
            || self.publication
            || self.active_publication
            || self.deletion_job
            || self.topology_operation
    }
}

impl SurfaceTarget {
    /// Returns the nullable database ids used by the topology tables.
    pub(in crate::db) fn ids(self) -> (Option<i64>, Option<i64>) {
        match self {
            Self::Registry(id) => (Some(id), None),
            Self::BinaryCache(id) => (None, Some(id)),
        }
    }
}
