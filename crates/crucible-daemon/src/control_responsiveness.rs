//! Daemon-side forwarding for the control responsiveness contract.
//!
//! The daemon hosts sessions and serves the API transport. It does not define a
//! separate responsiveness rule: daemon routes validate the same quantum-counted
//! acknowledgement evidence as the in-process API path.

use crucible_api::{
    CONTROL_RESPONSIVE_QUANTUM_BOUND, ControlOperationAcknowledgement, ControlOperationKind,
    ControlResponsiveReport, ControlResponsiveSessionProbe, ControlResponsivenessError,
    validate_control_responsiveness,
};

/// Daemon acknowledgement latency bound, measured in scheduler quanta.
pub const DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND: u64 = CONTROL_RESPONSIVE_QUANTUM_BOUND;

/// Validates daemon-routed control responsiveness evidence.
///
/// # Errors
///
/// Returns [`ControlResponsivenessError`] when the daemon route evidence omits a
/// required operation, is not issued against a running session, moves backward in
/// quantum time, or exceeds [`DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND`].
pub fn validate_daemon_control_responsiveness(
    acknowledgements: &[ControlOperationAcknowledgement],
) -> Result<ControlResponsiveReport, ControlResponsivenessError> {
    validate_control_responsiveness(acknowledgements, DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND)
}

/// Daemon-side route for quantum-counted control-responsive probes.
#[derive(Clone)]
pub struct DaemonControlResponsiveRoute {
    probe: ControlResponsiveSessionProbe,
}

impl DaemonControlResponsiveRoute {
    /// Creates a daemon route over the API's in-process session probe.
    #[must_use]
    pub fn new(probe: ControlResponsiveSessionProbe) -> Self {
        Self { probe }
    }

    /// Issues one control operation through the daemon route.
    ///
    /// # Errors
    ///
    /// Returns [`ControlResponsivenessError`] when the underlying in-process API
    /// probe cannot send or observe the operation against a running session.
    pub async fn issue_against_running_session(
        &self,
        operation: ControlOperationKind,
    ) -> Result<ControlOperationAcknowledgement, ControlResponsivenessError> {
        self.probe.issue_against_running_session(operation).await
    }
}
