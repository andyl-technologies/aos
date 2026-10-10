//! Installed CNP-backed quantized nodes with actual retained process custody.
//!
//! Private launch and source qualification precede graph sealing. Public controls
//! preserve original request, input and operation identities; native outcomes
//! remain claims until checked by the installed measured checksum model. Complete
//! world activation uses the coordinator's opaque durable publication authority.
//! Unsupported exact execution, state preservation and causal input mappings
//! refuse explicitly while the original process remains supervised.

mod activation;
mod boundary;
mod control;
mod implementation;
mod input;
mod lifecycle;
mod lifecycle_resend;
mod lineage;
mod original_conflict;
mod pending;
mod preparation;
mod preparation_adverse;
mod preparation_probe;
mod preparation_resend;
mod process;
mod readiness;
mod windows;

pub use control::CnpControlledReference;
pub use lineage::{
    OriginalRuntimeLineage, with_completed_runtime_lineage, with_original_runtime_lineage,
};
pub use preparation::{CnpPreparationFailure, CnpReferencePreparation, CnpReferenceQualification};
pub use process::{CnpLaunchFailure, CnpLaunchGuard, CnpPeerCustody, CnpProcessCustodySlot};

/// Runs an actual installed public checksum node under the common quantized runtime.
pub type CnpReferenceNode =
    super::reference_device::ControlledReferenceNode<CnpControlledReference>;

#[cfg(test)]
mod tests;

pub use preparation_probe::{CnpPreRealizationProbeBody, CnpPreRealizationProbeRequest};

pub use preparation_adverse::{CnpPreparedAdverseBody, CnpPreparedAdverseRequest};

pub use lifecycle_resend::{
    CnpCompletedLifecyclePhase, CnpCompletedLifecycleQualification, CnpCompletedLifecycleScope,
};

pub use original_conflict::CnpOriginalConflictQualification;

mod lineage_reader;

pub use lineage_reader::{
    LineageControlledReference, LineagePreparationFailure, LineageReferenceQualification,
    LineageRuntimeCustody, LineageRuntimeCustodySlot,
};
