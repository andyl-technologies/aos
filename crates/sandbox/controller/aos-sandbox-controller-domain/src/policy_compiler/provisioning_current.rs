//! Owns fresh purpose-specific Root provisioning comparison consumers.
//!
//! Native Source/Cache observations use a genuine new Apply or HostLaunch R
//! borrower. These modules do not adopt old Root8/Source17/Held authority or
//! create a signed plan, accepted operation or publication from comparison DATA.

mod environment;
pub(crate) use environment::RootEnvironmentReadonlyContextV1;

mod receiving;
mod native_views;
pub(crate) use native_views::RootProvisioningNativeViewsV1;
pub(in crate::policy_compiler) use native_views::{
    TreeDataV1, maintenance_tree_model_receiving_demand_v3, maintenance_tree_model_data_v3,
};

mod environment_compiler;
pub(crate) use environment_compiler::RootEnvironmentCompilerOriginalV1;

mod compiler_geometry;
pub(crate) use compiler_geometry::current_compiler_complete_receiving_demand_v1;

mod horizon;
pub(crate) use horizon::{RootContinuationHorizonDataV1, RootContinuationClockGateV1};

pub(in crate::policy_compiler) mod ownership_trust;
pub(crate) mod apply_inputs;
pub(crate) mod apply_readonly;
pub(crate) mod apply_compiler;
mod parentless_compiler;
pub(crate) use parentless_compiler::compile_parentless_current_v1;
pub(in crate::policy_compiler) use parentless_compiler::require_manifest_candidate_v1;

pub(crate) mod create_finality;
pub(crate) mod finality_readonly;

mod historical_create_session;

mod start_assignment;
pub(crate) use start_assignment::{
    StartAssignmentCompilationDataV2, StartAssignmentCompilationResultV2,
    compile_accepted_start_assignment_v2,
};

pub(crate) mod current_manifest;
pub(crate) mod current_cleanup_assignment;
pub(in crate::policy_compiler) use historical_create_session::{
    HistoricalCreateSessionOriginalV1, HistoricalStorageHistoryBorrowV2,
};


pub(in crate::policy_compiler) use start_assignment::require_current_start_signed_inputs_v2;

// The actual Root consumer shares the compiler through this named boundary.
pub(in crate::policy_compiler) use start_assignment::{
    compile_root_start_assignment_v2, root_start_compilation_control_bytes_v2,
};
