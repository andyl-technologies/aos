//! Protected publication-root registry and Linux live descriptor custody.
//!
//! Durable records bind logical placement and policy only. Paths, file
//! descriptors, device numbers, inode numbers, and mount identifiers never
//! become authority. A caller must pair a current active registry record with a
//! fresh, nonpersisted observation of an already protected Linux directory.
//! The canonical record, codec, recovery, and registry remain portable; live
//! descriptor custody is compiled only on Linux.

#[cfg(target_os = "linux")]
mod custody;
mod format;
mod model;
mod recovery;
mod registry;

#[cfg(target_os = "linux")]
pub(crate) use custody::FreshServiceObservationV1;
#[cfg(target_os = "linux")]
pub use custody::{AuthorizedPublicationRoot, PublicationRootCustody, RootObservationError};
pub use format::{RootRecordCodecError, decode_root_record_v1, encode_root_record_v1};
pub use model::{
    PublicationFilesystemProfileV1, PublicationRootId, PublicationRootObligationsV1,
    PublicationRootRecordV1, PublicationRootRoleV1, PublicationRootStateV1,
};
pub use recovery::{
    RootRecoveryDispositionV1, RootRecoveryEntryV1, RootRecoveryReportV1, reduce_root_recovery_v1,
};
#[cfg(target_os = "linux")]
pub use registry::CurrentPublicationRoot;
pub(crate) use registry::registry_digest;
pub use registry::{
    PublicationRootRegistry, PublicationRootRegistryCheckpointV1, PublicationRootRegistryError,
};
