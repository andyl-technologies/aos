//! Pure portable semantic compilers for hostile protocol requests.
//!
//! These modules depend only on protobuf input, shared protocol validation,
//! and portable core authority types. They never accept or emit backend paths,
//! dataset names, GUIDs, encryption keys, or other node-local expressions.

pub mod storage;

pub use storage::{
    CanonicalStorageSemanticsV1, CatalogBindingV1, StorageOperation, StorageSemanticsError,
};
