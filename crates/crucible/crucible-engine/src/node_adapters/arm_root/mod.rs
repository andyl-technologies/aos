//! Adapts the fixed source-installed ARM root model to common node ownership.
//!
//! This adapter consumes genuine model-aware Serial receipts and independent
//! current opaque process authority. It never converts UART events into SE
//! stdout identities or derives readiness from a portable profile commitment.
//! Preparation, execution and signed continuation retain their original native
//! and common permission histories under finite supervisor custody.

use crate::node_contract::{EffectKnowledge, OperationFailure};

mod ancestry;
mod boundary_dependencies;
mod capture;
mod continuation;
mod encoding;
mod execution;
mod ledger;
mod node;
mod preparation;
mod preparation_mapping;
mod restore;

pub use capture::{
    ARM_ROOT_CONTINUATION_SPECIFICATION, ARM_ROOT_PRESERVATION_PROFILE, ArmRootArchiveInstallation,
    arm_root_continuation_schema,
};
pub use continuation::{AuthenticatedArmRootContinuation, authenticate_arm_root_continuation};
pub use node::{
    ARM_ROOT_SERIAL_INTERFACE, ARM_ROOT_SERIAL_SCHEMA, ARM_ROOT_SERIAL_SPECIFICATION,
    ArmRootNodeResources, ArmRootQualifiedFailure, QualifiedArmRootNode,
};

pub use preparation::{
    ArmRootNodePreparation, ArmRootPreparationFailure, ArmRootPreparationQualification,
};

/// Names the distinct source-installed ARM common implementation.
pub const ARM_ROOT_IMPLEMENTATION: &str = "gem5/arm-root-native-process-v1";

/// Names the fixed parent-zero ARM Linux root computation model.
pub const ARM_ROOT_MODEL: &str = "arm-linux-vexpress-atomic-root-functional-v1";

/// Names the model-aware native Serial protocol without SE fallback.
pub const ARM_ROOT_DIALECT: &str = "crucible.gem5.arm-linux-native/1";

/// Names the installed exact root Serial mediation profile.
pub const ARM_ROOT_EXACT_PROFILE: &str = "gem5/arm-root-serial-exact-v1";

fn refusal(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod encoding_tests;

#[cfg(test)]
mod ancestry_tests;
