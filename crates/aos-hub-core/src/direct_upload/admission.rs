//! Server-resolved admission snapshots and compact verified placement evidence.

use serde::{Deserialize, Serialize};

use crate::storage_authority::lease::LeaseCohort;

use super::{DirectManifestCommitment, DirectUploadIntent, WireInteger};

/// Exact physical domain independently matched against the broker configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectPhysicalContext {
    /// Deployment R2 with an independently configured bucket association.
    DeploymentR2 {
        /// Immutable deployment/bucket guard domain.
        deployment_id: String,
        /// Independently configured permanent bucket namespace identity.
        bucket_namespace: String,
    },
    /// External provider authority qualified for this exact staging protocol.
    External {
        /// Immutable admitted write cohort; freshness needs a real current lease.
        write_cohort: Box<LeaseCohort>,
        /// Separately admitted read cohort for staging verification/copy source.
        read_cohort: Box<LeaseCohort>,
    },
}

/// Credential identity, never credential material or a provider URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectCredentialRevision {
    /// Exact purpose, either write or presign.
    pub purpose: String,
    /// Retained purpose-specific credential identity.
    pub credential_id: String,
    /// Exact retained credential generation.
    pub generation: WireInteger,
    /// Immutable independently published secret-version locator, never the secret.
    pub secret_version_ref: String,
    /// Exact material/coordinate commitment of the independently resolved credential.
    pub credential_fingerprint: String,
}

/// Independently configured private-stage policy commitment.
///
/// A configuration/signature is not evidence that provider policy is enforced;
/// the broker separately requires actual qualified policy readback/evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPrivateStagePolicyRef {
    /// Stable reviewed policy identity.
    pub policy_id: String,
    /// Exact policy/evidence commitment.
    pub policy_digest: String,
    /// Exact private staging namespace or bucket namespace.
    pub namespace: String,
}

/// Required destination frozen before any provider session is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPlacement {
    /// Required placement row identity.
    pub placement_id: WireInteger,
    /// Exact placement resource version.
    pub placement_resource_version: WireInteger,
    /// Exact placement write specification version.
    pub write_spec_version: WireInteger,
    /// Exact storage binding row identity.
    pub binding_id: WireInteger,
    /// Exact binding resource version.
    pub binding_resource_version: WireInteger,
    /// Exact binding write revision.
    pub binding_write_revision: WireInteger,
    /// Server-resolved full final object key; absent from public grants/status.
    pub final_key: String,
    /// Server-resolved private staging namespace; clients cannot select it.
    pub staging_prefix: String,
    /// Exact configured policy governing private stage visibility and grants.
    pub private_stage_policy: DirectPrivateStagePolicyRef,
    /// Whole independently reviewed actual protected profile captured before first staging.
    /// Old admissions cannot default this pin or adopt a later profile on replay.
    pub protected_profile_digest: String,
    /// Qualified exact checksum for this destination, announced before grants.
    pub checksum_algorithm: super::DirectChecksumAlgorithm,
    /// Exact independent provider/bucket authority projection.
    pub physical: DirectPhysicalContext,
    /// Exact write credential publication used for server-owned controls.
    pub write_credential: DirectCredentialRevision,
    /// Exact read credential publication for independent staging verification.
    pub read_credential: DirectCredentialRevision,
    /// Exact presign credential publication used for delegated staging parts.
    pub presign_credential: DirectCredentialRevision,
}

/// Authenticated Native admission, checked before broker provider effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadAdmission {
    /// Stable logical session identity, independent of mutable source inputs.
    pub session_id: String,
    /// Stable authenticated principal identity.
    pub principal_id: String,
    /// Exact Native account slot/incarnation, reserved before business admission.
    pub actor_slot: super::DirectActorSlot,
    /// Exact immutable source/owner/geometry declaration.
    pub intent: DirectUploadIntent,
    /// Fingerprint of this complete immutable admission projection.
    pub logical_fingerprint: String,
    /// Exclusive logical eligibility deadline; no provider settlement inference.
    pub expires_at: WireInteger,
    /// Sorted unique required placement snapshots.
    pub placements: Vec<DirectPlacement>,
}

/// Compact independently verified final-object evidence for one destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectPlacementEvidence {
    /// Exact destination identity from admission.
    pub placement_id: WireInteger,
    /// Exact placement resource version from admission.
    pub placement_resource_version: WireInteger,
    /// Exact placement write specification version from admission.
    pub write_spec_version: WireInteger,
    /// Exact binding identity from admission.
    pub binding_id: WireInteger,
    /// Exact binding resource version from admission.
    pub binding_resource_version: WireInteger,
    /// Exact binding write revision from admission.
    pub binding_write_revision: WireInteger,
    /// Exact provider-specific complete manifest commitment.
    pub manifest: DirectManifestCommitment,
    /// Stable retained guarded promotion operation identity.
    pub promotion_operation_id: String,
    /// Provider upload/version incarnation of the verified immutable staging.
    pub staging_incarnation: DirectObjectIncarnation,
    /// Provider upload/version incarnation retained by final promotion.
    pub final_incarnation: DirectObjectIncarnation,
    /// Exact strong provider ETag of the promoted object.
    pub final_etag: String,
}

/// Signed broker proof consumed before Native advances logical visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectCompletionEvidence {
    /// Exact logical session identity.
    pub session_id: String,
    /// Exact immutable admission fingerprint.
    pub logical_fingerprint: String,
    /// Stable semantic complete operation identity.
    pub operation_id: String,
    /// Number of parts in the frozen complete manifest.
    pub part_count: u32,
    /// Independently verified full-object SHA-256, never a multipart ETag.
    pub sha256: String,
    /// Independently verified full-object length.
    pub byte_size: WireInteger,
    /// Sorted unique evidence for every required destination.
    pub placements: Vec<DirectPlacementEvidence>,
    /// Bounded parsed semantic fields; never original object bytes or text.
    pub projection: Option<crate::hybrid_ingress::HybridObjectProjection>,
}

/// Real object incarnation, independently of multipart provider session identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectObjectIncarnation {
    /// Provider-guaranteed unique object upload/version identifier, including R2.
    ProviderVersion {
        /// Exact provider object version; never a multipart UploadId.
        version: String,
    },
    /// Monotonic physical-key guard identity for nonversioned external storage.
    GuardStamp {
        /// Exact real guard-issued authority/generation stamp.
        stamp: crate::storage_authority::StorageGuardStamp,
    },
}

/// Verified immutable private-stage proof used before fresh final promotion ACL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectVerifiedStageEvidence {
    /// Original logical session identity.
    pub session_id: String,
    /// Original complete immutable admission fingerprint.
    pub logical_fingerprint: String,
    /// Stable complete operation whose retained stage is being promoted.
    pub operation_id: String,
    /// Complete exact part count, zero only for a real verified EmptyPut.
    pub part_count: u32,
    /// Independently streamed full original SHA-256.
    pub sha256: String,
    /// Independently verified exact original size.
    pub byte_size: WireInteger,
    /// Sorted exact stage evidence for every required destination.
    pub placements: Vec<DirectStagePlacementEvidence>,
    /// Bounded semantic projection used by Native's final dependency barriers.
    pub projection: Option<crate::hybrid_ingress::HybridObjectProjection>,
}

/// Positive immutable stage identity and complete manifest of one destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectStagePlacementEvidence {
    /// Exact full placement snapshot commitment from the original admission.
    pub placement: super::DirectPlacementRef,
    /// Exact complete provider-specific part manifest commitment.
    pub manifest: DirectManifestCommitment,
    /// Stable retained full-source verification operation identity.
    pub verification_operation_id: String,
    /// Actual object incarnation after a positive immutable close/EmptyPut.
    pub staging_incarnation: DirectObjectIncarnation,
}
