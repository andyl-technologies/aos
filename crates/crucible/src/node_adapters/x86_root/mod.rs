//! Adapts the fixed source-installed x86 root model to common node ownership.
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
    X86_ROOT_CONTINUATION_SPECIFICATION, X86_ROOT_PRESERVATION_PROFILE, X86RootArchiveInstallation,
    x86_root_continuation_schema,
};
pub use continuation::{AuthenticatedX86RootContinuation, authenticate_x86_root_continuation};
pub use node::{
    QualifiedX86RootNode, X86_ROOT_SERIAL_INTERFACE, X86_ROOT_SERIAL_SCHEMA,
    X86_ROOT_SERIAL_SPECIFICATION, X86RootNodeResources, X86RootQualifiedFailure,
};

pub use preparation::{
    X86RootNodePreparation, X86RootPreparationFailure, X86RootPreparationQualification,
};

/// Names the distinct source-installed x86 common implementation.
pub const X86_ROOT_IMPLEMENTATION: &str = "gem5/x86-root-native-process-v1";

/// Names the fixed parent-zero x86 Linux root computation model.
pub const X86_ROOT_MODEL: &str = "x86-linux-pc-atomic-root-functional-v1";

/// Names the model-aware native Serial protocol without SE fallback.
pub const X86_ROOT_DIALECT: &str = "crucible.gem5.x86-linux-native/1";

/// Names the installed exact root Serial mediation profile.
pub const X86_ROOT_EXACT_PROFILE: &str = "gem5/x86-root-serial-exact-v1";

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
