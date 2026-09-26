//! Closed persisted DTOs shared by Mount producers and journal validation.

use serde::{Deserialize, Serialize};

use crate::MountSourceProofClassV1;

/// Exact SourcePin schema tag.
pub const SOURCE_PIN_SCHEMA_V1: &str = "AOSMSP01";
/// Exact SourcePin schema version.
pub const SOURCE_PIN_FORMAT_VERSION_V1: u16 = 1;
/// Exact SourcePin key prefix.
pub const SOURCE_PIN_KEY_PREFIX_V1: &[u8] = b"aos.mount.source-pin.v1\0";
/// Maximum canonical SourcePin value size.
pub const MAXIMUM_SOURCE_PIN_VALUE_BYTES_V1: usize = 128 * 1024;
/// Exact Mount-resource schema version.
pub const MOUNT_RESOURCE_FORMAT_VERSION_V2: u16 = 2;
/// Exact Mount-resource key prefix.
pub const MOUNT_RESOURCE_KEY_PREFIX_V2: &[u8] = b"aos.mount.resource.v2\0";
/// Maximum canonical Mount-resource value size accepted by the shared codec.
pub const MAXIMUM_MOUNT_RESOURCE_VALUE_BYTES_V2: usize = 64 * 1024;

/// Records the lifecycle of one persisted SourcePin.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePinLifecycleV1 {
    /// Manager custody exists.
    Active,
    /// New references are forbidden and removal is pending.
    Reaping,
    /// Removal was acknowledged.
    Released,
}

/// Persists exact logical, provider, physical, and admission SourcePin state.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePinRowV1 {
    pub handle: [u8; 32],
    pub revision: u64,
    pub binding_bytes: Vec<u8>,
    pub binding_digest: [u8; 32],
    pub proof_class: MountSourceProofClassV1,
    pub provider_authority_id: [u8; 16],
    pub provider_authority_generation: u64,
    pub provider_authority_digest: [u8; 32],
    pub provider_resource_id: [u8; 32],
    pub provider_resource_generation: u64,
    pub provider_resource_digest: [u8; 32],
    pub provider_catalog_generation: u64,
    pub provider_catalog_digest: [u8; 32],
    pub kernel_boot_id: [u8; 16],
    pub device: u64,
    pub inode: u64,
    pub unique_mount_id: u64,
    pub physical_proof_digest: [u8; 32],
    pub admission_operation_id: [u8; 16],
    pub admission_request_digest: [u8; 32],
    pub current: bool,
    pub lifecycle: SourcePinLifecycleV1,
}

/// Wraps one canonical `AOSMSP01` row.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSourcePinV1 {
    pub schema: String,
    pub version: u16,
    pub row: SourcePinRowV1,
}

/// Binds a Mount resource to one controller assignment.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentBindingV1 {
    pub sandbox_id: [u8; 16],
    pub incarnation_id: [u8; 16],
    pub assignment_epoch: u64,
    pub desired_generation: u64,
    pub assignment_digest: [u8; 32],
    pub namespace_generation: u64,
}

/// Names a broker-owned mount attribute.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedMountAttributeV1 {
    ReadOnly,
    NoExec,
    NoSuid,
    NoDevice,
    NoAtime,
    Recursive,
}

/// Selects the closed filesystem-view mutation mode.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMutationV1 {
    ReadOnly,
    ReadWrite,
    PrivateCow,
    AppendOnly,
    Service,
}

/// Selects the source consistency contract.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountSourceConsistencyV1 {
    ImmutableRevision,
    LocalLive,
    BestEffortReplica,
}

/// Stores the canonical Mount policy.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountPolicyV1 {
    pub attributes: Vec<OwnedMountAttributeV1>,
    pub mutation: NativeMutationV1,
}

/// Stores one portable object descriptor.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDescriptorV1 {
    pub media_type: String,
    pub sha256_digest: [u8; 32],
    pub encoded_size: u64,
}

/// Stores the immutable source and destination of one Mount resource.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountRecipeV1 {
    pub attachment_id: [u8; 16],
    pub destination_slot_id: [u8; 16],
    pub view_revision: ObjectDescriptorV1,
    pub source_generation: u64,
    pub resource_attachment_generation: u64,
    pub source_view_id: [u8; 16],
    pub source_incarnation_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_assignment_digest: Option<[u8; 32]>,
    pub source_consistency: MountSourceConsistencyV1,
    pub source_handle: Vec<u8>,
    pub source_binding_digest: [u8; 32],
    pub source_realization_handle: [u8; 32],
    pub source_physical_proof_digest: [u8; 32],
    pub source_kernel_boot_id: [u8; 16],
    pub source_device: u64,
    pub source_inode: u64,
    pub source_proof_class: MountSourceProofClassV1,
    pub source_unique_mount_id: u64,
    pub source_provider_authority_id: [u8; 16],
    pub source_provider_authority_generation: u64,
    pub source_provider_authority_digest: [u8; 32],
    pub source_provider_resource_id: [u8; 32],
    pub source_provider_resource_generation: u64,
    pub source_provider_resource_digest: [u8; 32],
    pub source_provider_catalog_generation: u64,
    pub source_provider_catalog_digest: [u8; 32],
    pub policy: MountPolicyV1,
}

/// Correlates one accepted operation with its exact request.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCorrelationV1 {
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
}

/// Correlates an uncertain publication with its exact target.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationCorrelationV1 {
    pub operation: OperationCorrelationV1,
    pub target_mount_namespace_id: u64,
    pub target_namespace_generation: u64,
    pub replaces: Option<[u8; 32]>,
}

/// Identifies a detached mount retained by the descriptor store.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedMountIdentityV1 {
    pub unique_mount_id: u64,
}

/// Stores an independently observed installed mount.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledMountObservationV1 {
    pub unique_mount_id: u64,
    pub parent_mount_id: u64,
    pub target_mount_namespace_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub superblock_magic: u64,
    pub superblock_flags: u32,
    pub mount_attributes: u64,
    pub propagation: u64,
    pub root: Vec<u8>,
    pub mount_point: Vec<u8>,
    pub identity_map_digest: [u8; 32],
}

/// Names the phase in which a terminal Mount fault was recorded.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountFaultPhaseV1 {
    Allocated,
    Prepared,
    Publishing,
    Installed,
    Detaching,
    Draining,
    Releasing,
}

/// Stores the crash-recoverable Mount-resource lifecycle.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum MountResourceStateV1 {
    Allocated {
        creation: OperationCorrelationV1,
    },
    Prepared {
        detached: DetachedMountIdentityV1,
        creation: OperationCorrelationV1,
    },
    Publishing {
        detached: DetachedMountIdentityV1,
        publication: PublicationCorrelationV1,
    },
    Installed {
        detached: DetachedMountIdentityV1,
        installed: InstalledMountObservationV1,
        publication: PublicationCorrelationV1,
    },
    Detaching {
        detached: DetachedMountIdentityV1,
        installed: InstalledMountObservationV1,
        detachment: OperationCorrelationV1,
    },
    Draining {
        detached: DetachedMountIdentityV1,
        installed: InstalledMountObservationV1,
        replaced_by: [u8; 32],
    },
    Releasing {
        detached: DetachedMountIdentityV1,
        installed: Option<InstalledMountObservationV1>,
        release: OperationCorrelationV1,
        replaced_by: Option<[u8; 32]>,
    },
    Released {
        last_detached_mount_id: Option<u64>,
        last_installed_mount_id: Option<u64>,
    },
    Faulted {
        from: MountFaultPhaseV1,
        creation: Option<OperationCorrelationV1>,
        publication: Option<PublicationCorrelationV1>,
        detachment: Option<OperationCorrelationV1>,
        release: Option<OperationCorrelationV1>,
        replaced_by: Option<[u8; 32]>,
        detached: Option<DetachedMountIdentityV1>,
        installed: Option<InstalledMountObservationV1>,
        failure_digest: [u8; 32],
    },
}

/// Stores one immutable recipe and its current durable lifecycle state.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountResourceV1 {
    pub handle: [u8; 32],
    pub fd_store_key: [u8; 32],
    pub kernel_boot_id: [u8; 16],
    pub revision: u64,
    pub binding: AssignmentBindingV1,
    pub recipe: MountRecipeV1,
    pub state: MountResourceStateV1,
}

/// Wraps one canonical Mount-resource row.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMountResourceV1 {
    pub version: u16,
    pub resource: MountResourceV1,
}
