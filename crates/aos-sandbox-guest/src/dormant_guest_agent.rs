//! Fixed entry validation shared by the protected Guest service.
//!
//! The independently packaged concrete agent delegates its entry contract here.
//! This seam rejects caller-selected configuration before entering the supplied
//! service; protected bootstrap, transport, and process custody remain with it.

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

/// Executes the fixed protected Guest entry contract.
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

/// Reports failure from the fixed protected Guest entry seam.
#[derive(Debug, thiserror::Error)]
pub enum DormantGuestAgentMainErrorV1 {
    /// The fixed entry seam received a caller-selectable override.
    #[error("dormant guest agent accepts no command-line overrides")]
    UnexpectedArgument,
    /// The injected protected service stopped with an error.
    #[error("dormant guest agent service failed: {0}")]
    Service(String),
}
