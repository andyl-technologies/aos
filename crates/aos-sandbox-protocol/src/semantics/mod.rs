//! Pure portable semantic compilers for hostile protocol requests.
//!
//! These modules depend only on protobuf input, shared protocol validation,
//! and portable core authority types. They never accept or emit backend paths,
//! dataset names, GUIDs, encryption keys, or other node-local expressions.

pub mod host;
pub mod mount;
pub mod storage;

pub use host::{
    CanonicalHostSemanticsV1, HostSemanticError, canonical_host_semantics_v1, runtime_handle_v1,
    runtime_resource_handle,
};
pub use mount::{
    CanonicalMountSemanticsV1, MountCatalogBindingV1, MountSemanticError,
    canonical_mount_semantics_v1,
};

pub use storage::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageSemanticsError,
};
