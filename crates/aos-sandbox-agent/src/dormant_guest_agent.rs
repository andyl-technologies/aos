//! Independently executable dormant guest-agent entry seam.
//!
//! The independently packaged binary delegates its fixed entry contract here.
//! It remains dormant until a protected launcher supplies the transport loop
//! that owns handshake, supervision, and cold-reopen recovery.

use std::ffi::OsString;

/// Runs the protected guest-agent service after entry validation.
pub trait DormantGuestAgentServiceV1 {
    /// Service-specific failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Runs the single protected guest-agent service loop.
    ///
    /// # Errors
    ///
    /// Returns the service error when protected provisioning, transport, or
    /// process supervision cannot continue safely.
    fn run(&mut self) -> Result<(), Self::Error>;
}

/// Executes the dormant guest-agent entry contract.
///
/// The seam deliberately accepts no listener address, state root, executable,
/// or credential override. Those values belong to protected provisioning.
///
/// # Errors
///
/// Returns [`DormantGuestAgentMainErrorV1`] for arguments other than the
/// program name or when the injected protected service fails.
pub fn dormant_guest_agent_main_v1<Arguments, Service>(
    arguments: Arguments,
    service: &mut Service,
) -> Result<(), DormantGuestAgentMainErrorV1>
where
    Arguments: IntoIterator<Item = OsString>,
    Service: DormantGuestAgentServiceV1,
{
    let mut arguments = arguments.into_iter();
    let _program_name = arguments.next();
    if arguments.next().is_some() {
        return Err(DormantGuestAgentMainErrorV1::UnexpectedArgument);
    }
    service
        .run()
        .map_err(|error| DormantGuestAgentMainErrorV1::Service(error.to_string()))
}

/// Reports failure from the dormant guest-agent entry seam.
#[derive(Debug, thiserror::Error)]
pub enum DormantGuestAgentMainErrorV1 {
    /// The source-only binary seam received a caller-selectable override.
    #[error("dormant guest agent accepts no command-line overrides")]
    UnexpectedArgument,
    /// The injected protected service stopped with an error.
    #[error("dormant guest agent service failed: {0}")]
    Service(String),
}
