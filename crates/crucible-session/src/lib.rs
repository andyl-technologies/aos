//! `crucible-session` owns the live session actor.
//!
//! Spec index: RFC-0010 files 20.
//!
//! This L4 crate will drive one live runtime state, accept control requests at
//! quantum boundaries, and expose the session semantics specified by RFC-0010
//! file 20. It contains no raw QEMU or shared-memory access.
//!
//! Module map: the crate root owns [`SessionDriver`], the thin L4 adapter over
//! the engine [`QuantumLoop`]; future modules will split control messages from
//! session lifecycle state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use crucible::{QuantumLoop, QuantumOutcome, QuantumRequest, SchedulerError};

/// Drives the engine quantum loop from the L4 session boundary.
///
/// `SessionDriver` is deliberately thin: it owns no backend advancement API and
/// delegates every unit of virtual-time progress to the L3 [`QuantumLoop`].
pub struct SessionDriver<L> {
    quantum_loop: L,
}

impl<L> SessionDriver<L> {
    /// Creates a session driver around an engine quantum loop.
    #[must_use]
    pub fn new(quantum_loop: L) -> Self {
        Self { quantum_loop }
    }

    /// Returns the wrapped quantum loop.
    #[must_use]
    pub fn into_inner(self) -> L {
        self.quantum_loop
    }
}

impl<L: QuantumLoop> SessionDriver<L> {
    /// Drives exactly one engine quantum through the L3 scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the engine quantum loop rejects the
    /// request or cannot complete the quantum.
    pub fn drive_quantum(
        &mut self,
        request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.quantum_loop.drive_quantum(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{
        Configuration, ContentHash, QuantumOutcome, ScenarioDef, SchedulerError, VirtualTime,
    };

    #[test]
    fn session_driver_delegates_to_quantum_loop() {
        let config = Configuration::genesis(ScenarioDef {
            id: ContentHash::default(),
        });
        let request = QuantumRequest {
            configuration: config.clone(),
            control: Vec::new(),
        };
        let mut driver = SessionDriver::new(StubLoop);

        let outcome = driver.drive_quantum(request);

        assert_eq!(
            outcome.as_ref().map(|outcome| &outcome.configuration),
            Ok(&config)
        );
    }

    struct StubLoop;

    impl QuantumLoop for StubLoop {
        fn drive_quantum(
            &mut self,
            request: QuantumRequest,
        ) -> Result<QuantumOutcome, SchedulerError> {
            Ok(QuantumOutcome {
                configuration: request.configuration,
                frontier: VirtualTime { ticks: 0 },
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
            })
        }
    }
}
