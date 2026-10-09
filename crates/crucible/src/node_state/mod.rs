//! Complete backend-bound capture admission and inactive world restoration.
//!
//! [`admit_capture`] verifies the artifact against a sealed realized graph and
//! authenticates its entire bounded content closure. Native cut, domain,
//! schema, and provenance proofs remain the responsibility of the trusted
//! [`CaptureEvidence`] adapter. [`stage_restore`] prepares every owner and the
//! coordinator before the existing runtime activation barrier may publish a
//! replacement world. No serializer, process fork, or architectural projection
//! is treated as proof of exact continuation.
//!
//! This module introduces no writer for the existing exact-checkpoint format.
//! CNP/1 [`crucible_node_contract::CaptureManifest`] remains a separate portable
//! contract; native bytes are interpreted only by their qualified adapter.

mod closure;
mod evidence;
mod host;
mod staging_custody;
mod transaction;
mod validation;

#[cfg(test)]
mod tests;

pub use closure::VerifiedStateContent;
pub use evidence::*;
pub use host::*;
pub use staging_custody::{PreparedNativeCustody, PreparedRestoreAllocation};
pub use transaction::*;
pub use validation::{VerifiedCapture, admit_capture};

/// Classifies a refusal without concealing native uncertainty or resource limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateErrorCode {
    /// A portable record or selected schema is invalid or unsupported.
    Schema,
    /// A complete owner, domain, object, or content closure is absent.
    IncompleteClosure,
    /// Actual implementation, model, bindings, scope, or state format differs.
    Incompatible,
    /// An authenticated reference is corrupt or unavailable.
    Content,
    /// An allocation, reservation, object count, or dependency bound is exceeded.
    ResourceLimit,
    /// Qualified native cut, restoration, or custody evidence is unavailable.
    NativeEvidence,
    /// A source incarnation or saved live permission was offered for restoration.
    StaleAuthority,
    /// Preparation, readiness, or durable publication failed.
    Restoration,
}

/// Reports the component and stable failure classification of state admission.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("state {code:?} at {component}: {reason}")]
pub struct StateError {
    /// Selects the failed invariant category.
    pub code: StateErrorCode,
    /// Identifies the affected owner, content object, or transaction phase.
    pub component: String,
    /// Explains the refused obligation without claiming rollback.
    pub reason: String,
}

impl StateError {
    /// Constructs a classified diagnostic for a trusted native adapter.
    pub fn new(
        code: StateErrorCode,
        component: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            code,
            component: component.into(),
            reason: reason.into(),
        }
    }
}

pub(super) fn schema(error: impl std::fmt::Display) -> StateError {
    StateError::new(StateErrorCode::Schema, "capture", error.to_string())
}
