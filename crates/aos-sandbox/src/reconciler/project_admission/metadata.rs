//! Keeps private aliases for the complete Protocol metadata DATA owner.
//!
//! Native metadata regressions remain beside the protected admission graph.

pub(in crate::reconciler) use aos_sandbox_protocol::domain_ledger::project_admission_metadata::{
    MAXIMUM_RECORD_BYTES, ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata,
    ProjectAdmissionPhaseV1 as ProjectAdmissionPhase,
    RetainedRootProjectTerminalV1 as RetainedRootProjectTerminal,
};

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
