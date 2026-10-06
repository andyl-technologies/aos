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
mod successor_consumer;
mod successor_flight;
mod successor_owner;
use super::first_source_successor_records as successor_records;
mod transport;
mod wire;

pub use successor_consumer::{
    FailedOriginalFirstSourceSuccessorV2, FirstSourceSuccessorConsumerPhaseV2,
    FirstSourceSuccessorSelectionV2, HeldControllerFirstSourceSuccessorV2,
    OriginalFirstSourceSuccessorInvocationV2, HeldControllerProjectSuccessorV3,
    OriginalProjectSuccessorInvocationV3, FailedProjectSuccessorInvocationV3,
};
pub(crate) use successor_consumer::ControllerSuccessorOwnerViewV3;
pub(crate) use successor_consumer::unavailable_first_source_successor_v2;
pub(crate) use successor_consumer::{unavailable_project_successor_v3, unavailable_predecessor_successor_v3};
pub use successor_flight::{HeldRootFirstSourceSuccessorIntentV2, RootFirstSourceSuccessorFloorProofV2,
    HeldRootProjectSuccessorIntentV3, RootProjectSuccessorFloorProofV3};
pub(crate) use successor_flight::{RootSuccessorIntentViewV3, RootSuccessorFloorViewV3};
pub(in crate::policy_compiler) use successor_flight::CompletedRootFirstSourceSuccessorFloorV2;
pub(in crate::policy_compiler) use successor_flight::CompletedRootProjectSuccessorFloorV3;
pub use successor_owner::RootFirstSuccessorMutationResultsV2;
pub(crate) use successor_owner::RootSuccessorNativeServerCutV3;
pub use current::CurrentRootFirstSourceSuccessorFloorV2;
pub use current::CurrentRootProjectSuccessorFloorV3;

pub use successor_records::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
};
pub(crate) use successor_records::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorBeginFieldsV2,
    ControllerFirstSourceSuccessorCompleteFieldsV2, RootFirstSourceSuccessorFloorFieldsV2,
    RootFirstSourceSuccessorIntentFieldsV2, SourceFirstSuccessorAckFieldsV2,
    SourceFirstSuccessorPendingFieldsV2, SourceFirstSuccessorReceiptFieldsV2,
};
pub(crate) use successor_owner::{
    require_root_first_source_successor_capacity_owner_v2,
    validate_root_first_source_successor_state_v2,
    validate_root_first_source_successor_transition_v2,
};

pub(crate) use capacity::{
    require_mutation as require_root_source_genesis_mutation_v1,
    require_owner as require_root_source_genesis_capacity_owner_v1,
    validate_admission as validate_root_source_genesis_capacity_admission_v1,
    validate_settlement as validate_root_source_genesis_capacity_settlement_v1,
};
pub use controller_readback::{
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1, CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2,
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
pub(in crate::policy_compiler) use controller_readback::ControllerGenesisReadbackPacketV2;
pub use coordinator::coordinate_provisioned_source_genesis_v1;
pub use coordinator::{OriginalConfiguredProjectGenesisInvocationV3, FailedConfiguredProjectGenesisInvocationV3};
pub(crate) use coordinator::unavailable_project_genesis_v3;
pub use successor_issuance::{
    FailedOriginalSourceSuccessorInvocationV2, OriginalSourceSuccessorInvocationV2,
    OriginalSourceProjectSuccessorInvocationV3, FailedSourceProjectSuccessorInvocationV3,
    SourceSuccessorIssuancePhaseV2,
};
pub(crate) use successor_issuance::{
    SourceSuccessorSigningCutV2, SourceSuccessorSigningCutV3,
    unavailable as unavailable_source_successor_issuer_v2,
    unavailable_project_issuer_v3,
};
pub use current::CurrentRootSourceGenesisFloorV1;
pub use current::CurrentRootSourceProjectGenesisFloorV3;
pub(in crate::policy_compiler) use flight::CompletedRootSourceGenesisFloorV1;
pub(in crate::policy_compiler) use flight::OriginalRootGenesisFlightV1;
pub(in crate::policy_compiler) use flight::{
    kernel_pair as original_root_kernel_pair_v1, require_open_receive_queue,
};
pub use flight::{HeldRootSourceGenesisIntentV1, RootSourceGenesisFloorProofV1};
pub use flight::{HeldRootSourceProjectGenesisIntentV3, RootSourceProjectGenesisFloorProofV3};
pub(crate) use flight::CompletedRootSourceProjectGenesisFloorV3;
pub use flight::observe_root_first_source_successor_clock_v2;
pub use records::{
    ROOT_SOURCE_GENESIS_INTENT_BYTES_V1, ROOT_SOURCE_GENESIS_INTENT_BYTES_V2,
    RootSourceGenesisIntentRecordV1,
    SOURCE_GENESIS_DEPLOYMENT_INSTANCE_BYTES_V1, SOURCE_HIERARCHY_FLOOR_BYTES_V1,
    SOURCE_HIERARCHY_FLOOR_BYTES_V2,
    SourceHierarchyFloorRecordV1,
};
pub use store::{
    RootFirstSourceSuccessorOpeningV2, RootSourceGenesisAuthorityV1,
    RootProjectGenesisMutationResultsV3,
    fixed_root_source_genesis_recovery_available_v1,
};
pub(in crate::policy_compiler) use store::Q04RootGen1CutLoanV1;

// Both original-flight owners use the same bounded readiness wait. The
// purpose-specific owner checks remain in their respective live loans.
pub(in crate::policy_compiler) fn wait_original_root_v1(
    descriptor: std::os::fd::BorrowedFd<'_>,
    interest: rustix::event::PollFlags,
    deadline: std::time::Instant,
) -> Result<(), crate::hierarchy::genesis_profile::SourceGenesisErrorV1> {
    transport::wait(descriptor, interest, deadline)
}
#[cfg(target_os = "linux")]
pub(in crate::policy_compiler) use wire::{
    RootCreateQ04TransferKindV1, decode_root_create_q04_transfer_v1,
    encode_root_create_q04_transfer_v1,
    strict_genesis_payload_bytes_from_header, q04_genesis_refresh_payload_bytes_from_header,
};
pub use wire::{
    ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1, ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    ROOT_SOURCE_GENESIS_QUERY_MAGIC_V1, RootSourceGenesisFrameKindV1,
    decode_root_source_genesis_frame_v1, encode_root_source_genesis_frame_v1,
    decode_root_source_genesis_frame_v2, encode_root_source_genesis_frame_v2,
};
pub use wire::{
    ROOT_SOURCE_PROJECT_GENESIS_QUERY_MAGIC_V3, ROOT_SOURCE_PROJECT_GENESIS_HELLO_MAGIC_V3,
    encode_root_source_project_genesis_frame_v3, decode_root_source_project_genesis_frame_v3,
    root_source_project_genesis_payload_bytes_v3,
};
pub use wire::{
    ROOT_FIRST_SOURCE_SUCCESSOR_HELLO_MAGIC_V2, ROOT_FIRST_SOURCE_SUCCESSOR_QUERY_MAGIC_V2,
    ROOT_PROJECT_SOURCE_SUCCESSOR_HELLO_MAGIC_V3, ROOT_PROJECT_SOURCE_SUCCESSOR_QUERY_MAGIC_V3,
    RootFirstSourceSuccessorFrameKindV2, decode_root_first_source_successor_frame_v2,
    encode_root_first_source_successor_frame_v2,
    encode_root_project_source_successor_frame_v3, decode_root_project_source_successor_frame_v3,
};
