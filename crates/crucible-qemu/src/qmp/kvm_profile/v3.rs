//! Edition-three native kernel component observations with no execution authority.
//!
//! The command and checked response stay separate from the original namespace.
//! A response proves only the reported component state of an independently
//! authenticated peer. It never qualifies userspace exit, timer, device, input,
//! output or whole-world physical stop custody.

use super::{
    QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpKvmClockComponentState, QmpKvmClockRequest,
    QmpTimeoutStream, parse_clock_component_edition, validate_clock_request_for,
};

/// Retains an edition-three response checked against its exact partial coverage.
///
/// Its constructor is private. The checked state is an observation, rather than
/// an installed profile, native stop receipt, activation or publication seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKvmClockV3ComponentState {
    observed: QmpKvmClockComponentState,
}

impl QmpKvmClockV3ComponentState {
    /// Borrows the checked component observation, whose profile remains unqualified.
    pub fn observed(&self) -> &QmpKvmClockComponentState {
        &self.observed
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Executes one bounded edition-three native clock component transaction.
    ///
    /// The source-patched emulator must select kernel edition three before vCPU
    /// creation. The original command cannot configure or control this edition.
    /// The caller authenticates the executable and peer independently; this
    /// method cannot turn partial coverage into a runnable node capability.
    ///
    /// # Errors
    /// Refuses invalid bounds before I/O, native or bounded transport failures,
    /// a response outside schema three and bitmap 159, changed generation or
    /// coordinates, incoherent RUN-owner observations, or profile qualification.
    pub fn control_native_kvm_clock_v3_component(
        &mut self,
        request: &QmpKvmClockRequest,
    ) -> Result<QmpKvmClockV3ComponentState, QmpError> {
        validate_clock_request_for(request, QmpCommandKind::KvmClockComponentV3)?;

        let response = self.send_command_return(QmpCommand::KvmClockComponentV3 { request })?;
        parse_v3_component(request, &response.value)
    }
}

fn parse_v3_component(
    request: &QmpKvmClockRequest,
    value: &serde_json::Value,
) -> Result<QmpKvmClockV3ComponentState, QmpError> {
    let observed =
        parse_clock_component_edition(request, value, QmpCommandKind::KvmClockComponentV3, 3, 159)?;
    Ok(QmpKvmClockV3ComponentState { observed })
}

#[cfg(test)]
#[path = "v3_tests.rs"]
mod tests;
