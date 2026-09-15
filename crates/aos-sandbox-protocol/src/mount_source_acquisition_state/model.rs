//! Canonical nonauthorizing model for the `AOSMSA02` namespace-40 format.
//!
//! The five record bodies are public so protected owners can correlate exact
//! typed journal bytes across crate boundaries. Constructing or decoding a
//! shaped record is never evidence of current provider authority.

use serde::{Deserialize, Serialize};

use crate::mount_manager_startup::StartupCleanupSourceSubjectV1;

/// Identifies one stable holder, provider, route, and resource namespace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderScopeV2 {
    pub holder_authority_id: [u8; 16],
    pub provider_authority_id: [u8; 16],
    pub route_id: [u8; 16],
    pub resource_namespace_digest: [u8; 32],
}

/// Binds one Mount acquisition to its holder-scoped SourceProvider identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAcquisitionIdentityV2 {
    pub holder_authority_id: [u8; 16],
    pub holder_authority_generation: u64,
    pub holder_authority_digest: [u8; 32],
    pub acquisition_sequence: u64,
    pub acquisition_id: [u8; 32],
}

/// Names one controller-issued Mount operation and exact body.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountOperationV2 {
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
}

/// Retains one exact assignment lineage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentV2 {
    pub sandbox_id: [u8; 16],
    pub incarnation_id: [u8; 16],
    pub assignment_epoch: u64,
    pub desired_generation: u64,
    pub assignment_digest: [u8; 32],
    pub namespace_generation: u64,
}

/// Retains the dominating teardown fence and predecessor compare-and-swap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAuthorityV2 {
    pub sandbox_id: [u8; 16],
    pub incarnation_id: [u8; 16],
    pub assignment_epoch: u64,
    pub desired_generation: u64,
    pub assignment_digest: [u8; 32],
    pub expected_revision: u64,
    pub expected_record_digest: [u8; 32],
}

/// Names the exact durable phase of one source acquisition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAcquisitionPhaseV2 {
    /// A provider Acquire may be pending or awaiting recovery.
    PendingQuery,
    /// A verified descriptor was handed to the manager but is not usable.
    DescriptorCustodied,
    /// Authoritative manager readback proved custody.
    Active,
    /// Source-pin and Create admission consumed the acquisition atomically.
    Consumed,
    /// Provider release is durably fenced.
    Releasing,
    /// Provider terminality and manager absence are proven.
    Released,
    /// A sanitized fault retains its effective predecessor phase.
    Faulted,
}

/// Maps SourceProvider proofs to Mount's three closed source classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAcquisitionProofClassV2 {
    /// An immutable publisher tree or held ZFS snapshot.
    ImmutableTree,
    /// A kernel-coupled local-live export.
    LocalLive,
    /// A reconstructible best-effort replica.
    BestEffortReplica,
}

/// Identifies a record by immutable ID, revision, and digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRefV2 {
    pub id: [u8; 32],
    pub revision: u64,
    pub record_digest: [u8; 32],
}

/// Identifies the closed SourceProvider operation of an attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMethodV2 {
    Acquire,
    Release,
    Inventory,
}

impl ProviderMethodV2 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Acquire => 1,
            Self::Release => 2,
            Self::Inventory => 3,
        }
    }
}

/// Identifies the stable owner of one immutable query lineage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "owner_kind", rename_all = "snake_case")]
pub enum ProviderQueryOwnerV2 {
    Acquire { acquisition_id: [u8; 32] },
    Release { acquisition_id: [u8; 32] },
    Inventory,
}

impl ProviderQueryOwnerV2 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Acquire { .. } => 1,
            Self::Release { .. } => 2,
            Self::Inventory => 3,
        }
    }

    pub const fn owner_id(self) -> [u8; 32] {
        match self {
            Self::Acquire { acquisition_id } | Self::Release { acquisition_id } => acquisition_id,
            Self::Inventory => [0; 32],
        }
    }
}

/// Commits the session-independent meaning of an Acquire lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireIntentV2 {
    pub scope: ProviderScopeV2,
    pub acquisition_id: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub mount_request: Vec<u8>,
    pub mount_request_digest: [u8; 32],
    pub assignment: AssignmentV2,
    pub mount_plan_digest: [u8; 32],
    pub ownership_lease_digest: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub prospective_mount_template: Vec<u8>,
    pub prospective_mount_template_digest: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub source_binding: Vec<u8>,
    pub source_binding_digest: [u8; 32],
    pub requested_lease_seconds: u64,
    pub requested_maximum_submounts: u32,
    pub recursive: bool,
    pub kernel_coupled: bool,
}

/// Retains the exact session-specific AOSNPI01 version-2 normalization of an Acquire.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptNormalizedAcquireV2 {
    #[serde(with = "super::format::canonical_bytes")]
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub maximum_lease_expiry_seconds: i64,
}

/// Retains the exact minimum catalog head authorized before an Acquire query.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCatalogFloorSnapshotV2 {
    /// Stable SourceProvider authority whose catalog is bounded.
    pub provider_authority_id: [u8; 16],
    /// Exact resource namespace bounded by the catalog floor.
    pub resource_namespace_digest: [u8; 32],
    /// Lowest acceptable signed catalog generation.
    pub minimum_catalog_generation: u64,
    /// Exact digest at the minimum catalog generation.
    pub minimum_catalog_digest: [u8; 32],
    /// Canonical protocol commitment to the complete floor.
    pub digest: [u8; 32],
}

/// Commits every rollback and exact-selection floor supplied before Acquire I/O.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireVerificationFloorV2 {
    /// Required stable provider catalog floor.
    pub catalog: ProviderCatalogFloorSnapshotV2,
    /// Exact protected current catalog-head commitment authenticated before I/O.
    pub current_catalog_head_commitment: Option<[u8; 32]>,
    /// Optional exact resource-selection floor fixed before provider I/O.
    pub selection: Option<SelectionFloorSnapshotV2>,
    /// Canonical digest paired exactly with `selection` presence.
    pub selection_digest: Option<[u8; 32]>,
}

/// Commits a bounded Release-Inventory fence from an acquisition predecessor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInventoryFenceWitnessV2 {
    pub inventory_observation_floor: u64,
    pub projection_epoch: u64,
    pub projection_digest: [u8; 32],
    pub projection_entry_count: u32,
}

/// Commits the security-relevant projection of an acquisition predecessor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionPredecessorWitnessV2 {
    pub record: RecordRefV2,
    pub acquisition_id: [u8; 32],
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    pub phase: SourceAcquisitionPhaseV2,
    pub scope: ProviderScopeV2,
    pub acquire: MountOperationV2,
    pub acquire_intent_digest: [u8; 32],
    pub acquire_lineage: QueryLineageV2,
    pub acquire_terminal_attempt: Option<RecordRefV2>,
    pub release: Option<MountOperationV2>,
    pub release_authority: Option<ReleaseAuthorityV2>,
    pub release_from_phase: Option<SourceAcquisitionPhaseV2>,
    pub release_intent_digest: Option<[u8; 32]>,
    pub release_lineage: Option<QueryLineageV2>,
    pub release_terminal_attempt: Option<RecordRefV2>,
    pub release_inventory_fence: Option<ReleaseInventoryFenceWitnessV2>,
    pub assignment: AssignmentV2,
    pub prospective_mount_template_digest: [u8; 32],
    pub source_binding_digest: [u8; 32],
    pub mount_plan_digest: [u8; 32],
    pub ownership_lease_digest: [u8; 32],
    pub evidence: Option<SourceAcquisitionEvidenceV2>,
    pub manager_custody: Option<ManagerCustodyEvidenceV2>,
    pub manager_custody_loss: Option<ManagerCustodyLossEvidenceV2>,
    pub descriptor_custody_digest: Option<[u8; 32]>,
    pub positive_custody_digest: Option<[u8; 32]>,
    pub consumption: Option<ConsumptionEvidenceV2>,
    pub release_proof: Option<ReleaseProofV2>,
    pub negative_custody_digest: Option<[u8; 32]>,
    pub faulted_from: Option<SourceAcquisitionPhaseV2>,
    pub fault_digest: Option<[u8; 32]>,
    pub retained_faulted_from: Option<SourceAcquisitionPhaseV2>,
    pub retained_fault_digest: Option<[u8; 32]>,
    pub recovery: AcquisitionRecoveryV2,
}

/// Classifies the non-interchangeable manager absence behind cleanup-only Release.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerCustodyLossKindV2 {
    /// No manager handoff completed before startup proved absence.
    NoPriorCustody,
    /// The prior manager belonged to an earlier kernel boot.
    BootReplaced,
    /// The retained prior-manager pidfd proved exit.
    PidfdExited,
    /// The numeric prior-manager process identity was reused.
    ProcessReplaced,
}

/// Persists the exact startup loss proof consumed to enter cleanup-only Release.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerCustodyLossEvidenceV2 {
    /// Exact pre-Release row and retained evidence selected by startup capture.
    pub subject: StartupCleanupSourceSubjectV1,
    /// Immutable complete startup capture identity.
    pub capture_id: [u8; 32],
    /// Exact canonical startup capture record digest.
    pub capture_record_digest: [u8; 32],
    /// Closed absence/death classification.
    pub kind: ManagerCustodyLossKindV2,
    /// Startup-issued commitment to absence and any prior-manager death.
    pub death_commitment: [u8; 32],
    /// Canonical digest of all preceding fields.
    pub evidence_digest: [u8; 32],
}

/// Commits the complete bounded projection of a provider-head predecessor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHeadPredecessorWitnessV2 {
    pub record: RecordRefV2,
    pub scope: ProviderScopeV2,
    pub holder_authority_generation: u64,
    pub holder_authority_digest: [u8; 32],
    pub provider_authority_generation: u64,
    pub provider_authority_digest: [u8; 32],
    pub current_session_id: [u8; 32],
    pub current_session_record_digest: [u8; 32],
    pub next_request_sequence: u64,
    pub next_response_sequence: u64,
    pub pending_attempt: Option<RecordRefV2>,
    pub inventory_observation_ordinal: u64,
    pub inventory_floor: Option<InventoryFloorV2>,
    pub last_inventory_attempt: Option<RecordRefV2>,
    pub current_projection_epoch: u64,
    pub current_projection_digest: [u8; 32],
    pub last_reconciliation: Option<ReconciliationV2>,
    pub recovery_barrier: Option<RecoveryBarrierV2>,
}

/// Retains a compact exact witness of the owner read before reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "owner_record_kind",
    rename_all = "snake_case"
)]
pub enum OwnerPredecessorWitnessV2 {
    Acquisition {
        value: AcquisitionPredecessorWitnessV2,
    },
    ProviderHead {
        value: ProviderHeadPredecessorWitnessV2,
    },
}

/// Commits the session-independent meaning of a Release lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIntentV2 {
    pub scope: ProviderScopeV2,
    pub acquisition_id: [u8; 32],
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    #[serde(with = "super::format::canonical_bytes")]
    pub mount_request: Vec<u8>,
    pub mount_operation: MountOperationV2,
    pub authority: ReleaseAuthorityV2,
    pub lease_id: [u8; 16],
    pub signed_lease_digest: [u8; 32],
    pub provider_resource_id: [u8; 32],
    pub provider_resource_digest: [u8; 32],
    pub provider_proof_digest: [u8; 32],
    pub descriptor_commitment: [u8; 32],
}

/// Commits the stable rollback floor of an Inventory lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryIntentV2 {
    pub scope: ProviderScopeV2,
    pub known_inventory_generation: Option<u64>,
    pub known_inventory_digest: Option<[u8; 32]>,
    pub known_catalog_generation: Option<u64>,
    pub known_catalog_digest: Option<[u8; 32]>,
    pub known_observation_ordinal: u64,
    pub recovery_root_attempt_id: Option<[u8; 32]>,
    /// Digest of the exact correlation preimage fixed before provider I/O.
    pub correlation_digest: [u8; 32],
}

/// Names the exact lease-state expectation fixed before an Inventory request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCorrelationExpectationV2 {
    /// A not-yet-evidenced acquisition may be absent or have become Active.
    AbsentOrMatchingActive,
    /// The retained lease must be Active or Reaping.
    PresentActiveOrReaping,
    /// A releasing lease may be Reaping, Released, or absent.
    ReapingReleasedOrAbsent,
    /// A terminal lease may be Released or absent.
    ReleasedOrAbsent,
}

/// Commits one exact acquisition/lease correlation at Inventory reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryCorrelationV2 {
    /// Stable Mount acquisition identity used by later Release proof joins.
    pub mount_acquisition_id: [u8; 32],
    /// Authority-scoped provider acquisition identity.
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    /// Exact lease identifier.
    pub lease_id: Option<[u8; 16]>,
    /// Digest of the exact signed provider lease.
    pub signed_lease_digest: Option<[u8; 32]>,
    /// Exact retained acquisition record fixed before provider I/O.
    pub acquisition_record: RecordRefV2,
    /// Closed lease-state expectation at reservation time.
    pub expectation: InventoryCorrelationExpectationV2,
}

/// Retains the bounded, ordered Inventory correlation preimage and digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryCorrelationSetV2 {
    /// Provider-acquisition-ID-sorted exact correlations.
    pub entries: Vec<InventoryCorrelationV2>,
    /// Digest of the exact ordered correlation preimage.
    pub digest: [u8; 32],
}

/// Stores one of the three immutable query intents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "intent_kind", rename_all = "snake_case")]
pub enum ProviderIntentV2 {
    Acquire { value: AcquireIntentV2 },
    Release { value: ReleaseIntentV2 },
    Inventory { value: InventoryIntentV2 },
}

impl ProviderIntentV2 {
    pub const fn scope(&self) -> ProviderScopeV2 {
        match self {
            Self::Acquire { value } => value.scope,
            Self::Release { value } => value.scope,
            Self::Inventory { value } => value.scope,
        }
    }
}

/// Identifies the closed SourceProvider disposition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatusV2 {
    Complete,
    Pending,
    Rejected,
    Unavailable,
}

/// Names the two admissible provider-death proofs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadProviderExecutionProofKindV2 {
    PidfdExited,
    BootReplaced,
}

/// Retains the safe durable projection of a dead provider execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeadProviderExecutionProjectionV2 {
    pub proof_kind: DeadProviderExecutionProofKindV2,
    pub old_session_id: [u8; 32],
    pub old_session_record_digest: [u8; 32],
    pub node_id: [u8; 16],
    pub old_kernel_boot_id: [u8; 16],
    pub provider_process_instance: [u8; 16],
    pub process_execution_digest: [u8; 32],
    pub observed_kernel_boot_id: [u8; 16],
    pub death_evidence_digest: [u8; 32],
}

/// Records the exact Inventory evidence resolving an indeterminate attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInventoryProofV2 {
    pub inventory_attempt: RecordRefV2,
    pub inventory_digest: [u8; 32],
    pub inventory_observation_ordinal: u64,
    pub projection_epoch: u64,
    pub projection_digest: [u8; 32],
    pub reconciliation: ReconciliationV2,
    pub reconciliation_digest: [u8; 32],
}

/// Records the exact Inventory evidence resolving an indeterminate attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    tag = "resolution_kind",
    rename_all = "snake_case"
)]
pub enum RecoveryResolutionV2 {
    RetryAcquireSameIntent {
        proof: RecoveryInventoryProofV2,
    },
    RetryReleaseSameIntent {
        proof: RecoveryInventoryProofV2,
    },
    ProviderTerminalObserved {
        proof: RecoveryInventoryProofV2,
    },
    InventoryReconciled {
        proof: RecoveryInventoryProofV2,
    },
    Conflict {
        proof: RecoveryInventoryProofV2,
        conflict_digest: [u8; 32],
    },
}

/// Commits the trusted time at which one exact provider outcome was verified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeVerificationAnchorV2 {
    pub verification_started_seconds: i64,
    pub verification_completed_seconds: i64,
    pub kernel_boot_id: [u8; 16],
    pub trusted_clock_evidence_digest: [u8; 32],
    pub anchor_digest: [u8; 32],
}

/// Stores the closed durable state of an immutable provider attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
pub enum ProviderAttemptStateV2 {
    Reserved,
    DispositionConsumed {
        response_sequence: u64,
        verification_anchor: OutcomeVerificationAnchorV2,
        status: ProviderStatusV2,
        #[serde(with = "super::format::canonical_bytes")]
        signed_status: Vec<u8>,
        signed_status_digest: [u8; 32],
        #[serde(with = "super::format::canonical_bytes")]
        signed_result: Vec<u8>,
        signed_result_digest: [u8; 32],
    },
    AbandonedIndeterminate {
        dead_execution: DeadProviderExecutionProjectionV2,
        successor_session_id: [u8; 32],
        recovery_root_attempt_id: [u8; 32],
        outcome_may_exist: bool,
        resolution: Option<RecoveryResolutionV2>,
    },
}

/// Stores one immutable SourceProvider query attempt and its terminal evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProviderQueryAttemptV2 {
    pub attempt_id: [u8; 32],
    pub revision: u64,
    pub scope: ProviderScopeV2,
    pub method: ProviderMethodV2,
    pub owner: ProviderQueryOwnerV2,
    pub intent: ProviderIntentV2,
    pub provider_acquisition: Option<ProviderAcquisitionIdentityV2>,
    pub immutable_intent_digest: [u8; 32],
    pub lineage_root_attempt_id: [u8; 32],
    pub previous_attempt_id: Option<[u8; 32]>,
    pub attempt_number: u64,
    pub session_id: [u8; 32],
    pub session_record_digest: [u8; 32],
    pub signer_set_commitment: [u8; 32],
    pub trust_digest: [u8; 32],
    pub revocation_digest: [u8; 32],
    pub route_digest: [u8; 32],
    pub process_execution_digest: [u8; 32],
    pub normalized_acquire_intent: Option<AttemptNormalizedAcquireV2>,
    pub acquire_verification_floor: Option<AcquireVerificationFloorV2>,
    /// Exact Inventory correlation preimage; present only for Inventory.
    pub inventory_correlations: Option<InventoryCorrelationSetV2>,
    pub request_id: [u8; 16],
    pub request_sequence: u64,
    #[serde(with = "super::format::canonical_bytes")]
    pub signed_request: Vec<u8>,
    pub signed_request_digest: [u8; 32],
    pub owner_predecessor_revision: u64,
    pub owner_predecessor_digest: [u8; 32],
    pub owner_predecessor: Option<OwnerPredecessorWitnessV2>,
    pub state: ProviderAttemptStateV2,
    pub record_digest: [u8; 32],
}

/// Retains one provider authority generation from protected trust.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTrustSnapshotV2 {
    pub authority_id: [u8; 16],
    pub authority_generation: u64,
    pub authority_digest: [u8; 32],
    pub valid_from_seconds: i64,
    pub valid_until_seconds: i64,
    pub state: AuthorityAdmissionStateV2,
}

/// Is the sole authority state permitted at session admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAdmissionStateV2 {
    Trusted,
}

/// Names one of the four physically separated signing roles.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRoleV2 {
    RootMountHello,
    RootMountRecord,
    ProviderHello,
    ProviderOutcome,
}

/// Is the sole key state permitted at session admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAdmissionStateV2 {
    Eligible,
}

/// Retains one exact signer and raw key from protected trust.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSnapshotV2 {
    pub role: SignerRoleV2,
    pub authority_id: [u8; 16],
    pub authority_generation: u64,
    pub authority_digest: [u8; 32],
    pub key_id: [u8; 16],
    pub key_generation: u64,
    pub public_key: [u8; 32],
    pub public_key_fingerprint: [u8; 32],
    pub authority_valid_from_seconds: i64,
    pub authority_valid_until_seconds: i64,
    pub key_valid_from_seconds: i64,
    pub key_valid_until_seconds: i64,
    pub authority_state: AuthorityAdmissionStateV2,
    pub key_state: KeyAdmissionStateV2,
    pub superseded_by_key_generation: u64,
}

/// Retains the negotiated proof and traversal capability intersection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedCapabilitiesV2 {
    pub proof_class_capabilities: u8,
    pub supports_recursive: bool,
    pub supports_kernel_coupled: bool,
    pub signed_lease_receipts: bool,
    pub separated_signing_roles: bool,
}

/// Retains every PIDFD_GET_INFO credential field without a liveness claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionSnapshotV2 {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub start_time_ticks: u64,
    pub cgroup_id: u64,
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub filesystem_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub filesystem_gid: u32,
    pub process_execution_digest: [u8; 32],
}

/// Retains the authenticated process that actually wrote the Root Mount hello.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActualWriterRootMountSnapshotV2 {
    pub uid: u32,
    pub gid: u32,
    pub tgid: u32,
    pub start_time_ticks: u64,
    pub cgroup_digest: [u8; 32],
}

/// Stores one immutable authenticated SourceProvider session snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProviderSessionV2 {
    pub session_id: [u8; 32],
    pub revision: u64,
    pub predecessor_session_id: Option<[u8; 32]>,
    pub scope: ProviderScopeV2,
    pub node_id: [u8; 16],
    pub kernel_boot_id: [u8; 16],
    pub root_mount_authority_generation: u64,
    pub root_mount_authority_digest: [u8; 32],
    pub provider_authority_generation: u64,
    pub provider_authority_digest: [u8; 32],
    pub route_generation: u64,
    pub route_digest: [u8; 32],
    pub negotiated_capabilities: NegotiatedCapabilitiesV2,
    #[serde(with = "super::format::canonical_bytes")]
    pub signed_root_mount_hello: Vec<u8>,
    pub signed_root_mount_hello_digest: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub signed_provider_hello: Vec<u8>,
    pub signed_provider_hello_digest: [u8; 32],
    pub session_binding: [u8; 32],
    pub signer_set_commitment: [u8; 32],
    pub authenticated_at_seconds: i64,
    pub current_valid_until_seconds: i64,
    pub trusted_clock_evidence_digest: [u8; 32],
    pub trust_generation: u64,
    pub trust_digest: [u8; 32],
    pub revocation_generation: u64,
    pub revocation_digest: [u8; 32],
    pub authority_trust: [AuthorityTrustSnapshotV2; 2],
    pub signers: [SignerSnapshotV2; 4],
    pub root_mount_process_instance: [u8; 16],
    pub actual_writer_root_mount_process: ActualWriterRootMountSnapshotV2,
    pub provider_process_instance: [u8; 16],
    pub provider_execution: ProviderExecutionSnapshotV2,
    pub record_digest: [u8; 32],
}

/// Retains the exact historical outcome signer and its selection-floor trust.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalLeaseSignerV2 {
    pub signer: SignerSnapshotV2,
    pub catalog_floor_provider_authority_id: [u8; 16],
    pub catalog_floor_resource_namespace_digest: [u8; 32],
    pub minimum_catalog_generation: u64,
    pub minimum_catalog_digest: [u8; 32],
    pub selection_floor: SelectionFloorSnapshotV2,
    pub selection_floor_digest: [u8; 32],
}

/// Is a complete isomorphic projection of `SourceSelectionFloorV1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionFloorSnapshotV2 {
    pub acquisition_id: [u8; 32],
    pub provider_authority_id: [u8; 16],
    pub route_id: [u8; 16],
    pub resource_namespace_digest: [u8; 32],
    pub catalog_generation: u64,
    pub catalog_digest: [u8; 32],
    pub resource_id: [u8; 32],
    pub resource_generation: u64,
    pub resource_digest: [u8; 32],
    pub selection_generation: u64,
    pub selection_digest: [u8; 32],
    pub outcome_signer_authority_id: [u8; 16],
    pub outcome_signer_authority_generation: u64,
    pub outcome_signer_authority_digest: [u8; 32],
    pub outcome_signer_key_id: [u8; 16],
    pub outcome_signer_key_generation: u64,
    pub outcome_signer_public_key_digest: [u8; 32],
    pub lease_id: [u8; 16],
    pub signed_lease_digest: [u8; 32],
    pub proof_class: u8,
    pub proof_digest: [u8; 32],
    pub resource_commitment: [u8; 32],
    pub trust_generation: u64,
    pub trust_digest: [u8; 32],
    pub revocation_generation: u64,
    pub revocation_digest: [u8; 32],
}

/// Commits a complete provider Inventory result retained in its attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryFloorV2 {
    pub attempt: RecordRefV2,
    pub provider_authority_generation: u64,
    pub provider_authority_digest: [u8; 32],
    pub provider_outcome_signer_digest: [u8; 32],
    pub inventory_generation: u64,
    pub inventory_digest: [u8; 32],
    pub catalog_generation: u64,
    pub catalog_digest: [u8; 32],
    pub signed_result_digest: [u8; 32],
}

/// Retains bounded reconciliation diagnostics for one exact projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationV2 {
    pub projection_epoch: u64,
    pub projection_digest: [u8; 32],
    pub residual_count: u32,
    pub residual_digest: [u8; 32],
    pub conflict_count: u32,
    pub conflict_digest: [u8; 32],
}

/// Names the only provider states consistent with one projected acquisition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionExpectationV2 {
    AbsentOrMatchingActive,
    MatchingActive,
    MatchingActiveOrReaping,
    MatchingReleasedOrAbsent,
}

/// Is one canonical acquisition member of a provider projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionEntryV2 {
    pub acquisition_id: [u8; 32],
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    pub acquire_intent_digest: [u8; 32],
    pub release_intent_digest: Option<[u8; 32]>,
    pub expectation: ProjectionExpectationV2,
    pub lease_id: Option<[u8; 16]>,
    pub signed_lease_digest: Option<[u8; 32]>,
    pub provider_resource_id: Option<[u8; 32]>,
    pub provider_resource_generation: Option<u64>,
    pub provider_resource_state_digest: Option<[u8; 32]>,
    pub provider_resource_digest: Option<[u8; 32]>,
    pub provider_catalog_generation: Option<u64>,
    pub provider_catalog_digest: Option<[u8; 32]>,
    pub provider_selection_generation: Option<u64>,
    pub provider_selection_digest: Option<[u8; 32]>,
    pub provider_proof_class: Option<u8>,
    pub mount_proof_class: Option<SourceAcquisitionProofClassV2>,
    pub provider_proof_digest: Option<[u8; 32]>,
    pub release_generation: Option<u64>,
}

/// Suspends normal work until successor-session Inventory resolves ambiguity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBarrierV2 {
    pub root_attempt: RecordRefV2,
    pub baseline_inventory_ordinal: u64,
    pub required_session_id: [u8; 32],
    pub recovery_inventory_tail: Option<RecordRefV2>,
    pub replacement_count: u64,
}

/// Stores one stable provider scope's sequence, projection, and recovery head.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProviderHeadV2 {
    pub revision: u64,
    pub scope: ProviderScopeV2,
    pub holder_authority_generation: u64,
    pub holder_authority_digest: [u8; 32],
    pub provider_authority_generation: u64,
    pub provider_authority_digest: [u8; 32],
    pub current_session_id: [u8; 32],
    pub current_session_record_digest: [u8; 32],
    pub next_request_sequence: u64,
    pub next_response_sequence: u64,
    pub pending_attempt: Option<RecordRefV2>,
    pub inventory_observation_ordinal: u64,
    pub inventory_floor: Option<InventoryFloorV2>,
    pub last_inventory_attempt: Option<RecordRefV2>,
    pub current_projection_epoch: u64,
    pub current_projection_digest: [u8; 32],
    pub last_reconciliation: Option<ReconciliationV2>,
    pub recovery_barrier: Option<RecoveryBarrierV2>,
    pub record_digest: [u8; 32],
}

/// Owns the single non-reusable acquisition sequence for one stable holder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HolderSequenceV2 {
    pub revision: u64,
    pub holder_authority_id: [u8; 16],
    pub last_allocated_acquisition_sequence: u64,
    pub next_acquisition_sequence: u64,
    pub record_digest: [u8; 32],
}

/// Retains exact verified provider resource and descriptor evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionEvidenceV2 {
    pub acquire_attempt: RecordRefV2,
    pub outcome_verification_anchor: OutcomeVerificationAnchorV2,
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    pub session_id: [u8; 32],
    pub provider_outcome_signer_digest: [u8; 32],
    pub historical_lease_signer: HistoricalLeaseSignerV2,
    pub provider_resource_id: [u8; 32],
    pub provider_resource_generation: u64,
    pub provider_resource_digest: [u8; 32],
    pub provider_catalog_generation: u64,
    pub provider_catalog_digest: [u8; 32],
    pub provider_selection_generation: u64,
    pub provider_selection_digest: [u8; 32],
    pub provider_proof_class: u8,
    pub proof_class: SourceAcquisitionProofClassV2,
    pub provider_proof_digest: [u8; 32],
    pub lease_id: [u8; 16],
    pub signed_lease_digest: [u8; 32],
    pub lease_issued_seconds: i64,
    pub lease_expires_seconds: i64,
    pub source_realization_handle: [u8; 32],
    pub source_physical_proof_digest: [u8; 32],
    pub source_kernel_boot_id: [u8; 16],
    pub source_device: u64,
    pub source_inode: u64,
    pub source_unique_mount_id: u64,
    pub descriptor_commitment: [u8; 32],
}

/// Commits the exact companion records consumed by Active-to-Consumed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumptionEvidenceV2 {
    /// Exact holder-sequence revision used by the deterministic transaction ID.
    pub holder_sequence_revision: u64,
    /// Exact provider-head revision used by the deterministic transaction ID.
    pub provider_head_revision: u64,
    /// Exact globally nonreusable journal transaction identity.
    pub transaction_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub transport_request_digest: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub final_create_semantics: Vec<u8>,
    pub final_create_semantics_digest: [u8; 32],
    pub source_pin_record_digest: [u8; 32],
    pub create_effect_record_digest: [u8; 32],
    pub create_operation_record_digest: [u8; 32],
}

/// Orders Inventory terminality after an exact retained Release projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInventoryFenceV2 {
    pub inventory_observation_floor: u64,
    pub projection_epoch: u64,
    pub projection_digest: [u8; 32],
    pub projection_entries: Vec<ProjectionEntryV2>,
}

/// Retains either a Release receipt or exact Inventory proof of terminality.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "proof_kind", rename_all = "snake_case")]
pub enum ReleaseProofV2 {
    ProviderReceipt {
        attempt: RecordRefV2,
        release_generation: u64,
    },
    ProviderInventory {
        attempt: RecordRefV2,
        /// Exact acquisition predecessor fixed by the Inventory reservation.
        acquisition_predecessor: RecordRefV2,
        inventory_digest: [u8; 32],
        inventory_observation_ordinal: u64,
        projection_epoch: u64,
    },
}

/// Links a row to one contiguous immutable attempt lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryLineageV2 {
    pub root: RecordRefV2,
    pub tail: RecordRefV2,
    pub next_attempt_number: u64,
}

/// Retains acquisition-scoped recovery without copying attempt history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "recovery_state", rename_all = "snake_case")]
pub enum AcquisitionRecoveryV2 {
    Ready,
    InventoryRequired {
        root_attempt: RecordRefV2,
    },
    RetryPermitted {
        root_attempt: RecordRefV2,
    },
    Conflict {
        inventory_attempt: RecordRefV2,
        reconciliation_digest: [u8; 32],
        conflict_digest: [u8; 32],
    },
}

/// Identifies the non-interchangeable manager-custody admission path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagerCustodyOriginV2 {
    /// A fresh signed FD-store handoff completed a distinct positive readback.
    FreshControlReadback,
    /// A complete protected startup descriptor table adopted the retained root.
    StartupCapture,
}

/// Persists compact authenticated Mount-manager custody evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerCustodyEvidenceV2 {
    /// Non-interchangeable admission path.
    pub origin: ManagerCustodyOriginV2,
    /// Exact acquisition predecessor before custody admission or rebind.
    pub admission_predecessor: RecordRefV2,
    /// Provider attempt whose session last admitted manager custody.
    pub owner_attempt: RecordRefV2,
    /// Exact owning provider session.
    pub owner_session_id: [u8; 32],
    /// Exact owning provider-session record digest.
    pub owner_session_record_digest: [u8; 32],
    /// Current Mount-manager kernel boot.
    pub manager_kernel_boot_id: [u8; 16],
    /// Commitment to the complete manager execution identity.
    pub manager_execution_commitment: [u8; 32],
    /// Gap-free startup capture sequence.
    pub capture_sequence: u64,
    /// Immutable startup capture identity.
    pub capture_id: [u8; 32],
    /// Exact startup-capture record digest.
    pub capture_record_digest: [u8; 32],
    /// Full initial descriptor-table count.
    pub descriptor_count: u32,
    /// Exact activation-label count.
    pub activation_count: u32,
    /// Protected expected-descriptor count.
    pub expected_descriptor_count: u32,
    /// Total cleanup and terminal source-subject count.
    pub source_subject_count: u32,
    /// Cleanup-only source-subject count.
    pub cleanup_subject_count: u32,
    /// Terminal source-subject count.
    pub terminal_subject_count: u32,
    /// Commitment to the exact source entry in the manager inventory.
    pub source_entry_commitment: [u8; 32],
    /// Origin-specific startup or signed-control presence commitment.
    pub presence_commitment: [u8; 32],
    /// Digest of all preceding fields.
    pub evidence_digest: [u8; 32],
}

/// Stores one acquisition lifecycle row in `AOSMSA02`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAcquisitionRowV2 {
    pub acquisition_id: [u8; 32],
    pub provider_acquisition: ProviderAcquisitionIdentityV2,
    pub revision: u64,
    pub phase: SourceAcquisitionPhaseV2,
    pub scope: ProviderScopeV2,
    pub acquire: MountOperationV2,
    #[serde(with = "super::format::canonical_bytes")]
    pub mount_acquire_request: Vec<u8>,
    pub acquire_intent_digest: [u8; 32],
    pub acquire_lineage: QueryLineageV2,
    pub acquire_terminal_attempt: Option<RecordRefV2>,
    pub release: Option<MountOperationV2>,
    #[serde(with = "super::format::canonical_optional_bytes")]
    pub mount_release_request: Option<Vec<u8>>,
    pub release_authority: Option<ReleaseAuthorityV2>,
    pub release_from_phase: Option<SourceAcquisitionPhaseV2>,
    pub release_intent_digest: Option<[u8; 32]>,
    pub release_lineage: Option<QueryLineageV2>,
    pub release_terminal_attempt: Option<RecordRefV2>,
    pub release_inventory_fence: Option<ReleaseInventoryFenceV2>,
    pub assignment: AssignmentV2,
    #[serde(with = "super::format::canonical_bytes")]
    pub prospective_mount_template: Vec<u8>,
    pub prospective_mount_template_digest: [u8; 32],
    #[serde(with = "super::format::canonical_bytes")]
    pub source_binding: Vec<u8>,
    pub source_binding_digest: [u8; 32],
    pub mount_plan_digest: [u8; 32],
    pub ownership_lease_digest: [u8; 32],
    pub evidence: Option<SourceAcquisitionEvidenceV2>,
    pub manager_custody: Option<ManagerCustodyEvidenceV2>,
    pub manager_custody_loss: Option<ManagerCustodyLossEvidenceV2>,
    pub descriptor_custody_digest: Option<[u8; 32]>,
    pub positive_custody_digest: Option<[u8; 32]>,
    pub consumption: Option<ConsumptionEvidenceV2>,
    pub release_proof: Option<ReleaseProofV2>,
    pub negative_custody_digest: Option<[u8; 32]>,
    pub faulted_from: Option<SourceAcquisitionPhaseV2>,
    pub fault_digest: Option<[u8; 32]>,
    pub retained_faulted_from: Option<SourceAcquisitionPhaseV2>,
    pub retained_fault_digest: Option<[u8; 32]>,
    pub recovery: AcquisitionRecoveryV2,
    pub record_digest: [u8; 32],
}

/// Wraps one of the five exact namespace-40 record bodies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "record_kind", rename_all = "snake_case")]
pub enum StoredRecordV2 {
    Acquisition { value: SourceAcquisitionRowV2 },
    ProviderHead { value: SourceProviderHeadV2 },
    HolderSequence { value: HolderSequenceV2 },
    ProviderSession { value: SourceProviderSessionV2 },
    ProviderQueryAttempt { value: SourceProviderQueryAttemptV2 },
}

/// Is the sole accepted namespace-40 value envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEnvelopeV2 {
    pub schema: String,
    pub version: u16,
    pub record: StoredRecordV2,
}
