//! Existing-role local protected-Root anchoring of genuine Source genesis.
//!
//! Controller accepts the exact signed seed and independent project decision;
//! Source appends canonical Tree/lineage/receipt and a pending fence; Root's
//! semantic floor CAS settles its reserved suffix; actual Controller floor ACK
//! precedes Source ACK and Controller completion. Neither raw records nor
//! signatures alone create the non-detachable live Root flight proofs.
//! This profile excludes whole-host disk rollback resistance. Ordinary unsigned
//! Tree replay and later mutation authority remain closed.

#[cfg(test)]
mod capacity;
mod controller_readback;
mod coordinator;
mod global_coordinator;
#[cfg(test)]
mod current;
mod flight;
#[cfg(test)]
mod store;
mod successor_issuance;
mod successor_consumer;
mod successor_flight;
mod transport;

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

use aos_sandbox_ledger_replay::replay::phase_records::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
};
use aos_sandbox_ledger_replay::replay::phase_records::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorBeginFieldsV2,
    ControllerFirstSourceSuccessorCompleteFieldsV2, RootFirstSourceSuccessorFloorFieldsV2,
    RootFirstSourceSuccessorIntentFieldsV2, SourceFirstSuccessorAckFieldsV2,
    SourceFirstSuccessorPendingFieldsV2, SourceFirstSuccessorReceiptFieldsV2,
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
pub use global_coordinator::{OriginalConfiguredGlobalGenesisInvocationV2, FailedConfiguredGlobalGenesisInvocationV2};
pub(crate) use global_coordinator::unavailable_global_genesis_v2;
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
pub(crate) use flight::CompletedRootSourceGenesisFloorV1;
pub(in crate::policy_compiler) use flight::OriginalRootGenesisFlightV1;
pub(in crate::policy_compiler) use flight::{
    kernel_pair as original_root_kernel_pair_v1, require_open_receive_queue,
};
pub use flight::{HeldRootSourceGenesisIntentV1, RootSourceGenesisFloorProofV1};
pub use flight::{HeldRootSourceProjectGenesisIntentV3, RootSourceProjectGenesisFloorProofV3};
pub(crate) use flight::CompletedRootSourceProjectGenesisFloorV3;
pub use flight::observe_root_first_source_successor_clock_v2;

/// Reports additional controls for a flight embedded in a measured invocation.
pub(crate) fn root_flight_additional_control_bytes_v1() -> Option<usize> {
    flight::OriginalRootGenesisFlightV1::additional_control_bytes_v1()
}

/// Reports complete construction bytes for a separately resident Root flight.
///
/// Source-issue constructs its later original outside its measured Outer.
pub(crate) fn root_flight_detached_construction_bytes_v1() -> Option<usize> {
    std::mem::size_of::<flight::OriginalRootGenesisFlightV1<'_>>()
        .checked_add(root_flight_additional_control_bytes_v1()?)
}
