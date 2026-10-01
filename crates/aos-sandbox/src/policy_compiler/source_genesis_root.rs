//! Existing-role local protected-Root anchoring of genuine Source genesis.
//!
//! Controller accepts the exact signed seed and independent project decision;
//! Source appends canonical Tree/lineage/receipt and a pending fence; Root's
//! semantic floor CAS settles its reserved suffix; actual Controller floor ACK
//! precedes Source ACK and Controller completion. Neither raw records nor
//! signatures alone create the non-detachable live Root flight proofs.
//! This profile excludes whole-host disk rollback resistance. Ordinary unsigned
//! Tree replay and later mutation authority remain closed.

mod capacity;
mod controller_readback;
mod coordinator;
mod current;
mod flight;
mod pins;
mod records;
mod store;
mod successor_issuance;
mod transport;
mod wire;

pub(crate) use capacity::{
    require_mutation as require_root_source_genesis_mutation_v1,
    require_owner as require_root_source_genesis_capacity_owner_v1,
    validate_admission as validate_root_source_genesis_capacity_admission_v1,
    validate_settlement as validate_root_source_genesis_capacity_settlement_v1,
};
pub use controller_readback::{
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1,
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
pub use coordinator::coordinate_provisioned_source_genesis_v1;
pub use successor_issuance::{
    FailedOriginalSourceSuccessorInvocationV2, OriginalSourceSuccessorInvocationV2,
    SourceSuccessorIssuancePhaseV2,
};
pub(crate) use successor_issuance::{
    SourceSuccessorSigningCutV2, unavailable as unavailable_source_successor_issuer_v2,
};
pub use current::CurrentRootSourceGenesisFloorV1;
pub(in crate::policy_compiler) use flight::CompletedRootSourceGenesisFloorV1;
pub use flight::{HeldRootSourceGenesisIntentV1, RootSourceGenesisFloorProofV1};
pub use records::{
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, RootSourceGenesisIntentRecordV1,
    SOURCE_GENESIS_DEPLOYMENT_INSTANCE_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1,
    SourceHierarchyFloorRecordV1,
};
pub use store::{RootSourceGenesisAuthorityV1, fixed_root_source_genesis_recovery_available_v1};
pub use wire::{
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1, RootSourceGenesisFrameKindV1,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
};
