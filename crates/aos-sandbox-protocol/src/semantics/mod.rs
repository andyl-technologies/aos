//! Pure portable semantic compilers for hostile protocol requests.
//!
//! These modules depend only on protobuf input, shared protocol validation,
//! and portable core authority types. They never accept or emit backend paths,
//! dataset names, GUIDs, encryption keys, or other node-local expressions.
//! Their outputs are nonauthorizing plan-match tuples: portable object
//! descriptors may remain committed as data, but ancillary descriptors,
//! descriptor numbers, and kernel objects never become semantic authority.

pub mod destination_slot;
pub mod host;
pub mod host_attach_gate;
pub mod host_execution;
pub mod host_execution_argument;
pub mod host_output;
pub mod mount;
pub mod mount_scope;
pub mod mount_source_acquisition;
pub mod network;
pub mod payload_scope;
pub mod storage;
pub mod storage_guest_root;
pub mod storage_prepare;
pub mod storage_repair;

pub use destination_slot::{
    CanonicalDestinationSlotSemanticsV1, DestinationSlotSemanticError,
    canonical_destination_slot_semantics_v1,
};
pub use host::{
    CanonicalHostSemanticsV1, HostSemanticError, canonical_host_semantics_v1, runtime_handle_v1,
    runtime_resource_handle,
};
pub use host_attach_gate::{
    CanonicalHostAttachGateSemanticsV1, HostAttachGateSemanticErrorV1,
    canonical_host_attach_gate_semantics_v1, canonical_host_attach_readiness_semantics_v1,
    canonical_host_attach_route_query_semantics_v1,
};
pub use host_execution::{
    CanonicalHostExecutionSemanticsV1, HostExecutionSemanticErrorV1,
    canonical_host_execution_apply_semantics_v1, canonical_host_execution_query_semantics_v1,
    host_execution_apply_content_grant_v1, host_execution_apply_grant_v1,
    host_execution_query_content_grant_v1, host_execution_query_grant_v1,
};
pub use host_execution_argument::{
    CanonicalHostExecutionArgumentSemanticsV1, HostExecutionArgumentSemanticErrorV1,
    host_execution_argument_no_apply_grant_v1, host_execution_argument_observe_grant_v1,
    host_execution_argument_query_grant_v1, host_execution_argument_query_no_apply_grant_v1,
};
pub use host_output::{
    CanonicalHostOutputSemanticsV1, HostOutputSemanticErrorV1, host_output_query_grant_v1,
    host_output_reserve_grant_v1,
};
pub use mount::{
    CanonicalMountSemanticsV1, CanonicalPrecatalogMountCreateV1, DecodedCanonicalMountSemanticsV1,
    MountCatalogBindingV1, MountSemanticError, canonical_mount_semantics_v1,
    canonical_precatalog_mount_create_template_v1, decode_canonical_mount_semantics_v1,
    final_mount_create_matches_precatalog_template_v1, project_final_mount_create_semantics_v1,
};
pub use mount_source_acquisition::{
    CanonicalMountSourceAcquisitionSemanticsV1, MountSourceAcquisitionSemanticError,
    canonical_acquire_mount_source_semantics_v1,
    canonical_release_mount_source_acquisition_semantics_v1,
};
pub use network::{
    CanonicalNetworkSemanticsV1, MAXIMUM_NETWORK_ENDPOINTS, NetworkOperation, NetworkSemanticsError,
};
pub use storage::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageSemanticsError,
};
pub use storage_guest_root::{
    CanonicalStorageGuestRootArgumentsV1, CanonicalStorageGuestRootSemanticsV1,
    decode_storage_guest_root_response_v1,
};
pub use storage_prepare::{
    CanonicalStoragePreparationSemanticsV1, ProtectedStorageCreatePreparationV1,
    StoragePreparationOperationV1, StoragePreparationSemanticsError,
};
pub use storage_repair::{CanonicalStorageRepairSemanticsV1, StorageRepairSemanticsError};
