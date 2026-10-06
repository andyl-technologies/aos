//! Pure sandbox hierarchy and filesystem-view planning models.
//!
//! The protected-journal adapter durably binds the bounded reducers while
//! retaining exact postcommit facts. The Source genesis owner coordinates one
//! atomic seed append and a borrowed Controller/Root floor-ACK handoff. It does
//! not own broker activation, descriptors, or public runtime readiness.

pub mod accounting;
pub mod artifact_codec;
pub mod codec;
#[cfg(target_os = "linux")]
pub mod controller_genesis;
#[cfg(target_os = "linux")]
pub mod controller_genesis_input;
pub mod evidence;
pub mod exports;
pub mod genesis_profile;
pub mod graph;
pub mod history;
pub mod inspection;
pub mod model;
pub mod placement;
mod protected_evidence;
pub mod protected_journal;
pub mod realizer;
pub mod recovery;
pub(crate) mod source_floor;
pub(crate) mod source_genesis;
pub mod source_seed;
pub mod source_successor;
#[cfg(target_os = "linux")]
mod source_successor_materialization;
#[cfg(target_os = "linux")]
pub use source_successor_materialization::{
    HeldSourceFirstSuccessorObservationV2, SourceFirstSuccessorMutationFailureV2,
    SourceFirstSuccessorMutationResultsV2,
    SourceFirstSuccessorStateV2, acknowledge_source_first_successor_v2,
    append_source_first_successor_v2, observe_source_first_successor_v2,
    SourceProjectContinuationObservationV3, observe_source_project_continuation_v3,
};
#[cfg(target_os = "linux")]
pub(crate) use source_successor_materialization::{
    SourceSuccessorObservationViewV3,
    SourceProjectContinuationEvidenceV3,
    first_source_successor_inventory_uid_v2, require_first_successor_context_v2,
    append_source_project_continuation_v3, acknowledge_source_project_continuation_v3,
};
pub(crate) use tree_lineage::validate_source_first_successor_members_v2;
pub(crate) use tree_lineage::validate_source_project_continuation_members_v3;
pub(crate) use tree_lineage::validate_source_project_genesis_members_v3;
pub(crate) use tree_lineage::validate_source_project_continuation_members_from_genesis_data_v3;
pub(crate) use tree_lineage::validate_source_project_genesis_members_from_genesis_data_v3;
pub(crate) use tree_lineage::source_first_successor_tree_readback_v2;
pub use source_genesis::{
    HeldSourceTreeGenesisObservationV1, SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1,
    SourceTreeGenesisReceiptV1, SourceTreeGenesisStateV1, observe_source_tree_genesis_v1,
    observe_vacant_source_tree_genesis_project_v1,
};
#[cfg(target_os = "linux")]
pub use source_genesis::{acknowledge_source_tree_genesis_v1, append_source_tree_genesis_v1};
#[cfg(target_os = "linux")]
pub use source_genesis::HeldSourceProjectGenesisObservationV3;
pub mod state;
mod tree_lineage;
