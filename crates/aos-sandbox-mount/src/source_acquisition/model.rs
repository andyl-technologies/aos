//! Canonical in-memory and serde model for AOSMSA01 records.
//!
//! The closed enums and structs in this module are the exact namespace-40
//! acquisition and provider-head value model. Validation and journal framing
//! live in sibling modules.

use aos_sandbox_source_provider_protocol::{SourceProviderMethod, SourceProviderStatus};
use serde::{Deserialize, Serialize};

/// Names the exact durable phase of one source acquisition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAcquisitionPhaseV1 {
    /// The signed provider query may be pending, unsent, or ambiguously delivered.
    PendingQuery,
    /// The provider result and descriptor are durable and handed to PID 1.
    DescriptorCustodied,
    /// Authoritative PID 1 readback proved the exact descriptor name present.
    Active,
    /// The acquisition was atomically consumed by source-pin and Create admission.
    Consumed,
    /// Provider release was durably fenced before release I/O.
    Releasing,
    /// Provider terminality and authoritative PID 1 absence are both proven.
    Released,
    /// A sanitized terminal fault retained the exact preceding phase.
    Faulted,
}

/// Correlates one controller-issued Mount effect with its exact body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionOperationV1 {
    /// Nonzero Mount request ID.
    pub operation_id: [u8; 16],
    /// SHA-256 over the exact Mount method body.
    pub request_digest: [u8; 32],
}

/// Retains the assignment lineage authorized by the plan and ownership lease.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionAssignmentV1 {
    /// Logical sandbox identity.
    pub sandbox_id: [u8; 16],
    /// Sandbox incarnation identity.
    pub incarnation_id: [u8; 16],
    /// Monotonic assignment epoch.
    pub assignment_epoch: u64,
    /// Current desired generation.
    pub desired_generation: u64,
    /// Exact assignment semantics digest.
    pub assignment_digest: [u8; 32],
    /// Payload mount-namespace generation in the prospective Create.
    pub namespace_generation: u64,
}

/// Retains the exact current-or-dominating teardown fence and predecessor CAS.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionReleaseAuthorityV1 {
    /// Sandbox identity, which must equal the Acquire lineage.
    pub sandbox_id: [u8; 16],
    /// Sandbox incarnation, which must equal the Acquire lineage.
    pub incarnation_id: [u8; 16],
    /// Current teardown assignment epoch.
    pub assignment_epoch: u64,
    /// Current teardown desired generation.
    pub desired_generation: u64,
    /// Current teardown assignment digest.
    pub assignment_digest: [u8; 32],
    /// Exact predecessor revision authorized by the controller request.
    pub expected_revision: u64,
    /// Exact predecessor record digest authorized by the controller request.
    pub expected_record_digest: [u8; 32],
}

/// Captures the protected route, trust, session, and Root Mount holder snapshot.
///
/// Construction of this scalar record proves only shape. Production must load
/// it from protected Mount configuration and a branded authenticated session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProviderContextSnapshotV1 {
    /// Root Mount holder authority ID.
    pub holder_authority_id: [u8; 16],
    /// Root Mount holder generation.
    pub holder_generation: u64,
    /// Root Mount holder state digest.
    pub holder_authority_digest: [u8; 32],
    /// Current node identity.
    pub node_id: [u8; 16],
    /// Current kernel boot identity.
    pub kernel_boot_id: [u8; 16],
    /// Current revocation-state digest.
    pub revocation_digest: [u8; 32],
    /// Protected provider route ID.
    pub provider_route_id: [u8; 16],
    /// Protected provider route generation.
    pub provider_route_generation: u64,
    /// Protected provider route digest.
    pub provider_route_digest: [u8; 32],
    /// Protected stable provider authority ID.
    pub provider_authority_id: [u8; 16],
    /// Protected stable provider authority generation.
    pub provider_authority_generation: u64,
    /// Protected provider authority-state digest.
    pub provider_authority_digest: [u8; 32],
    /// Protected active provider key ID.
    pub provider_key_id: [u8; 16],
    /// Protected active provider key generation.
    pub provider_key_generation: u64,
    /// Protected provider Ed25519 key fingerprint.
    pub provider_public_key_digest: [u8; 32],
    /// Protected provider resource namespace.
    pub resource_namespace_digest: [u8; 32],
    /// Mutually signed SourceProvider hello transcript digest.
    pub session_binding: [u8; 32],
}

/// Retains one provider-signed disposition after atomic sequence consumption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDispositionCheckpointV1 {
    /// Closed SourceProvider method authenticated by the status envelope.
    pub method: ProviderMethodV1,
    /// Closed signed provider status.
    pub status: ProviderStatusV1,
    /// Client-to-provider sequence consumed by the transaction.
    pub request_sequence: u64,
    /// Provider-to-client sequence consumed by the transaction.
    pub response_sequence: u64,
    /// Digest of the complete signed provider request envelope.
    pub signed_request_digest: [u8; 32],
    /// Digest of the complete signed provider status envelope.
    pub signed_status_digest: [u8; 32],
    /// Digest of the exact optional result bytes.
    pub result_digest: [u8; 32],
    /// Exact signed request bytes retained for recovery and redelivery checks.
    pub signed_request: Vec<u8>,
    /// Exact signed status bytes retained for recovery and redelivery checks.
    pub signed_status: Vec<u8>,
    /// Exact optional signed result bytes retained for recovery.
    ///
    /// A Complete Inventory checkpoint leaves this empty because its provider
    /// head retains the same signed inventory bytes exactly once.
    pub signed_result: Vec<u8>,
}

/// Identifies the durable owner of one outstanding provider query.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "query_kind")]
pub enum ProviderQueryOwnerV1 {
    /// An Acquire query for the named acquisition row.
    Acquire { acquisition_id: [u8; 32] },
    /// A Release query for the named acquisition row.
    Release { acquisition_id: [u8; 32] },
    /// A holder-scoped provider inventory query.
    Inventory,
}

/// Retains one request whose client-to-provider sequence is already reserved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingProviderQueryV1 {
    /// Lifecycle operation that owns the reservation.
    pub owner: ProviderQueryOwnerV1,
    /// Exact request sequence reserved by the namespace-40 transaction.
    pub request_sequence: u64,
    /// Digest of the exact signed provider request envelope.
    pub signed_request_digest: [u8; 32],
    /// Exact signed provider request envelope, retained across ambiguous I/O.
    pub signed_request: Vec<u8>,
}

/// Mirrors the three closed SourceProvider methods without native enum persistence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMethodV1 {
    /// A source acquisition query.
    Acquire,
    /// A lease release query.
    Release,
    /// A holder-scoped source inventory query.
    Inventory,
}

impl ProviderMethodV1 {
    pub(super) const fn protocol(self) -> SourceProviderMethod {
        match self {
            Self::Acquire => SourceProviderMethod::Acquire,
            Self::Release => SourceProviderMethod::Release,
            Self::Inventory => SourceProviderMethod::Inventory,
        }
    }
}

/// Mirrors the closed SourceProvider status without native enum persistence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatusV1 {
    /// The operation completed with its exact nested signed result.
    Complete,
    /// The provider durably retained the operation as pending.
    Pending,
    /// The provider durably rejected the operation without an effect.
    Rejected,
    /// The provider signed that it could not currently answer.
    Unavailable,
}

impl From<SourceProviderStatus> for ProviderStatusV1 {
    fn from(value: SourceProviderStatus) -> Self {
        match value {
            SourceProviderStatus::Complete => Self::Complete,
            SourceProviderStatus::Pending => Self::Pending,
            SourceProviderStatus::Rejected => Self::Rejected,
            SourceProviderStatus::Unavailable => Self::Unavailable,
        }
    }
}

/// Retains stable provider lease, resource, proof, and descriptor evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionEvidenceV1 {
    /// Provider resource ID.
    pub provider_resource_id: [u8; 32],
    /// Provider resource generation.
    pub provider_resource_generation: u64,
    /// SourceProvider resource/proof commitment consumed by `AOSMSP01`.
    pub provider_resource_digest: [u8; 32],
    /// Provider catalog generation.
    pub provider_catalog_generation: u64,
    /// Provider catalog digest.
    pub provider_catalog_digest: [u8; 32],
    /// Protected-route selection generation.
    pub provider_selection_generation: u64,
    /// Protected-route selection digest.
    pub provider_selection_digest: [u8; 32],
    /// Closed Mount proof class, never a numeric cast from provider proof codes.
    pub proof_class: SourceAcquisitionProofClassV1,
    /// Exact provider proof digest.
    pub provider_proof_digest: [u8; 32],
    /// Exact provider lease ID.
    pub lease_id: [u8; 16],
    /// Digest of the complete signed provider lease envelope.
    pub signed_lease_digest: [u8; 32],
    /// Inclusive provider lease issue time.
    pub lease_issued_seconds: i64,
    /// Exclusive provider lease expiry time.
    pub lease_expires_seconds: i64,
    /// Mount-minted physical source realization handle.
    pub source_realization_handle: [u8; 32],
    /// Exact Stage-1 physical proof digest.
    pub source_physical_proof_digest: [u8; 32],
    /// Descriptor observation kernel boot.
    pub source_kernel_boot_id: [u8; 16],
    /// Descriptor device identity.
    pub source_device: u64,
    /// Descriptor inode identity.
    pub source_inode: u64,
    /// Descriptor unique mount identity.
    pub source_unique_mount_id: u64,
    /// Commitment to the adapter-branded descriptor observation.
    pub descriptor_commitment: [u8; 32],
}

/// Maps provider proof variants to the three Stage-1 Mount proof classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAcquisitionProofClassV1 {
    /// ZFS and immutable-publisher sources become immutable Mount trees.
    ImmutableTree,
    /// A kernel-coupled local-live export remains local-live.
    LocalLive,
    /// A reconstructible replica remains explicitly best effort.
    BestEffortReplica,
}

/// Proves a future kernel adapter branded the exact SourceRoot descriptor observation.
///
/// There is intentionally no public constructor. SourceProvider verification
/// accepts shaped scalar observations, so production acquisition remains
/// closed until the Linux adapter can mint this brand from kernel evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrandedSourceRootObservationV1 {
    pub(super) descriptor_commitment: [u8; 32],
}

/// Proves a protected adapter authenticated the current provider session head.
///
/// There is intentionally no public constructor. Public scalar context and
/// head records establish shape only and cannot seed production replay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProviderSessionV1 {
    pub(super) provider: SourceProviderContextSnapshotV1,
    pub(super) head: SourceProviderHeadV1,
}

/// Stores one exact `AOSMSA01` lifecycle row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionRowV1 {
    /// Mount-minted acquisition identity and namespace key suffix.
    pub acquisition_id: [u8; 32],
    /// Monotonic row revision.
    pub revision: u64,
    /// Current closed lifecycle phase.
    pub phase: SourceAcquisitionPhaseV1,
    /// Original controller Acquire operation.
    pub acquire: SourceAcquisitionOperationV1,
    /// Exact controller-to-Mount Acquire request body.
    pub mount_acquire_request: Vec<u8>,
    /// Controller Release operation, present from Releasing onward.
    pub release: Option<SourceAcquisitionOperationV1>,
    /// Exact validated controller-to-Mount Release request body.
    pub mount_release_request: Option<Vec<u8>>,
    /// Current-or-dominating teardown fence and exact predecessor CAS.
    pub release_authority: Option<SourceAcquisitionReleaseAuthorityV1>,
    /// Protected current provider session that signed the active Release query.
    pub release_provider: Option<SourceProviderContextSnapshotV1>,
    /// Provider inventory observation ordinal captured before first Release I/O.
    pub release_inventory_observation_floor: Option<u64>,
    /// Exact assignment lineage.
    pub assignment: SourceAcquisitionAssignmentV1,
    /// Exact prospective pre-catalog `AOSMSEM1` bytes.
    pub prospective_mount_template: Vec<u8>,
    /// SourceProvider prospective-template digest.
    pub prospective_mount_template_digest: [u8; 32],
    /// Canonical logical source binding bytes.
    pub source_binding: Vec<u8>,
    /// Canonical source-binding digest.
    pub source_binding_digest: [u8; 32],
    /// Digest of the controller-signed Mount plan.
    pub mount_plan_digest: [u8; 32],
    /// Digest of the current ownership lease.
    pub ownership_lease_digest: [u8; 32],
    /// Protected provider/session snapshot resolved by Mount.
    pub provider: SourceProviderContextSnapshotV1,
    /// Exact signed SourceProvider Acquire request durable before provider I/O.
    pub provider_acquire_request: Vec<u8>,
    /// SHA-256 of the exact signed SourceProvider Acquire request envelope.
    pub provider_acquire_request_digest: [u8; 32],
    /// Last durably consumed provider Acquire disposition, if one arrived.
    pub acquire_checkpoint: Option<ProviderDispositionCheckpointV1>,
    /// Earlier signed Acquire dispositions retained across provider Pending retries.
    pub acquire_history: Vec<ProviderDispositionCheckpointV1>,
    /// Complete verified provider and branded descriptor evidence after success.
    pub evidence: Option<SourceAcquisitionEvidenceV1>,
    /// Digest of the authoritative PID 1 descriptor-handoff acknowledgement.
    pub descriptor_custody_digest: Option<[u8; 32]>,
    /// Digest of authoritative PID 1 positive evidence, present from Active.
    pub positive_custody_digest: Option<[u8; 32]>,
    /// Digest of the exact AOSMSP01 activation record consumed with Create.
    pub consumed_source_pin_record_digest: Option<[u8; 32]>,
    /// Digest of the exact Create effect record consumed with the source pin.
    pub consumed_create_effect_record_digest: Option<[u8; 32]>,
    /// Digest of the exact Create operation record consumed with the source pin.
    pub consumed_create_operation_record_digest: Option<[u8; 32]>,
    /// Exact signed SourceProvider Release request durable before release I/O.
    pub provider_release_request: Option<Vec<u8>>,
    /// SHA-256 of the exact signed SourceProvider Release request envelope.
    pub provider_release_request_digest: Option<[u8; 32]>,
    /// Immutable first signed Release request retained for controller replay.
    pub initial_provider_release_request: Option<Vec<u8>>,
    /// Digest of the immutable first signed Release request.
    pub initial_provider_release_request_digest: Option<[u8; 32]>,
    /// Last durably consumed provider Release disposition.
    pub release_checkpoint: Option<ProviderDispositionCheckpointV1>,
    /// Earlier signed Release dispositions retained across provider Pending retries.
    pub release_history: Vec<ProviderDispositionCheckpointV1>,
    /// Monotonic provider release generation after terminal release.
    pub release_generation: Option<u64>,
    /// Digest of signed provider inventory establishing terminality, if used.
    pub provider_inventory_digest: Option<[u8; 32]>,
    /// Provider inventory observation ordinal establishing inventory terminality.
    pub provider_inventory_observation_ordinal: Option<u64>,
    /// Digest of authoritative PID 1 negative evidence in Released.
    pub negative_custody_digest: Option<[u8; 32]>,
    /// Exact source phase from which a fault was recorded.
    pub faulted_from: Option<SourceAcquisitionPhaseV1>,
    /// Sanitized terminal fault identity.
    pub fault_digest: Option<[u8; 32]>,
    /// Fault source retained when authenticated cleanup resumes from Faulted.
    pub retained_faulted_from: Option<SourceAcquisitionPhaseV1>,
    /// Fault digest retained when authenticated cleanup resumes from Faulted.
    pub retained_fault_digest: Option<[u8; 32]>,
    /// Digest over this canonical row with this field zeroed.
    pub record_digest: [u8; 32],
}

/// Stores atomic direction-sequence state and the durable inventory floor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProviderHeadV1 {
    /// Stable Root Mount holder authority ID.
    pub holder_authority_id: [u8; 16],
    /// Current Root Mount holder generation.
    pub holder_generation: u64,
    /// Current Root Mount holder authority-state digest.
    pub holder_authority_digest: [u8; 32],
    /// Stable provider authority ID.
    pub provider_authority_id: [u8; 16],
    /// Current provider authority generation.
    pub provider_authority_generation: u64,
    /// Current provider authority-state digest.
    pub provider_authority_digest: [u8; 32],
    /// Current signed-session binding.
    pub session_binding: [u8; 32],
    /// Current kernel boot for the session binding.
    pub kernel_boot_id: [u8; 16],
    /// Next required client-to-provider sequence.
    pub next_request_sequence: u64,
    /// Next required provider-to-client sequence.
    pub next_response_sequence: u64,
    /// Current protected route generation.
    pub route_generation: u64,
    /// Stable protected provider route ID.
    pub route_id: [u8; 16],
    /// Current protected route digest.
    pub route_digest: [u8; 32],
    /// Current protected provider key generation.
    pub provider_key_generation: u64,
    /// Current protected provider key ID.
    pub provider_key_id: [u8; 16],
    /// Current protected provider public-key digest.
    pub provider_public_key_digest: [u8; 32],
    /// Current protected provider resource-namespace digest.
    pub resource_namespace_digest: [u8; 32],
    /// Current protected revocation-state digest.
    pub revocation_digest: [u8; 32],
    /// Monotonic count of newly consumed Complete Inventory observations.
    pub inventory_observation_ordinal: u64,
    /// At most one durable request reservation for this signed session.
    pub pending_query: Option<PendingProviderQueryV1>,
    /// Highest authenticated provider inventory generation.
    pub inventory_generation: Option<u64>,
    /// Digest of the exact canonical inventory subject at the floor.
    pub inventory_digest: Option<[u8; 32]>,
    /// Digest of the exact complete signed inventory envelope.
    pub signed_inventory_digest: Option<[u8; 32]>,
    /// Exact complete signed inventory bytes at the floor.
    pub signed_inventory: Vec<u8>,
    /// Provider catalog generation at the floor.
    pub catalog_generation: Option<u64>,
    /// Provider catalog digest at the floor.
    pub catalog_digest: Option<[u8; 32]>,
    /// Last signed inventory disposition consumed by this session head.
    pub last_inventory_checkpoint: Option<ProviderDispositionCheckpointV1>,
    /// Diagnoses untracked leases in the row projection at last observation.
    pub has_untracked_inventory_residuals: bool,
    /// Diagnoses authority conflicts in the row projection at last observation.
    pub has_inventory_authority_conflicts: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "record_kind", rename_all = "snake_case")]
pub(super) enum StoredRecordV1 {
    Acquisition { row: SourceAcquisitionRowV1 },
    ProviderHead { head: SourceProviderHeadV1 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredEnvelopeV1 {
    pub(super) schema: String,
    pub(super) version: u16,
    pub(super) record: StoredRecordV1,
}
