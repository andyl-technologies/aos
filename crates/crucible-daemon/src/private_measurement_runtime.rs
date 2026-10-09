//! Owns the private daemon actor admission before its genuine packaged factory.
//!
//! The sole entry consumes the authenticated parent carrier and publishes its
//! original paired accounts through the closed actor issuer. A compiled exact
//! workflow and complete physical-purpose coverage remain prerequisites for
//! the genuine factory; actor arguments cannot provide either authority.

use crucible_linux_resource::host_services::HostServiceError;
use crucible_linux_resource::host_supervision::HostSupervisionError;
use crucible_linux_resource::measurement_origin::{
    AuthenticatedParentInvocation, MeasurementOriginError,
};

mod actor_roles;

pub use actor_roles::OriginalActorRoleIssuer;

/// First refusal while deriving the closed original actor from its actual issuer.
#[derive(Debug, thiserror::Error)]
pub enum MeasurementRuntimeAdmissionError {
    /// The actual issuer or same original absolute interval refused admission.
    #[error("original actor issuance refused: {0}")]
    Origin(#[from] MeasurementOriginError),
    /// A required compiled complete-purpose certificate is absent.
    #[error("original actor lacks compiled complete purpose at {0}")]
    MissingPurpose(&'static str),
    /// An absent purpose remains primary when the same original interval ends.
    #[error("original actor lacks {purpose}; post-original refusal: {after}")]
    MissingPurposeBoundary {
        /// Exact first omitted compiled purpose.
        purpose: &'static str,
        /// Same retained interval's separate postcheck refusal.
        after: MeasurementOriginError,
    },
    /// The same stack original paired accounts refused structural admission.
    #[error("original actor structural admission refused: {0}")]
    Account(#[from] HostServiceError),
    /// The same original supervisor or preparation refused publication.
    #[error("original actor supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// The same closed actor publication or external native credit refused.
    #[error("original actor account custody refused: {0}")]
    ActorAccounts(#[from] crucible_qemu::OriginalActorAccountError),
}

/// Runs the private actor through its authenticated parent and closed publisher.
///
/// The same consumed origin reaches the original supervisor; this entry cannot
/// receive a caller-authored bank, reset a clock or infer a launch permission
/// from an image inventory. The compiled workflow must subsequently select the
/// genuine packaged service and retain its same factory through retirement.
///
/// # Errors
/// Refuses original parent authentication or account publication. Until the
/// immutable workflow package is installed, retains the published custody and
/// refuses factory effects rather than substituting actor arguments.
pub fn run_original_actor() -> Result<(), MeasurementRuntimeAdmissionError> {
    let invocation = AuthenticatedParentInvocation::receive_original()?;
    let issuer = OriginalActorRoleIssuer::admit_parent(invocation)?;
    issuer.require_original()?;

    Err(MeasurementRuntimeAdmissionError::MissingPurpose(
        "installed immutable genuine workflow",
    ))
}
