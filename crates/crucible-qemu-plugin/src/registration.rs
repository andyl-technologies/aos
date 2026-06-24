//! Fail-stop sequencing for QEMU plugin registration.
//!
//! The QEMU FFI entry point will eventually call into this module around each
//! side-effecting operation. Keeping the ordering state machine safe and
//! testable here ensures the registration path remains:
//!
//! ```text
//! parse -> handshake -> time control -> setup -> callbacks -> ready ack -> boot barrier -> guest code
//! ```

use thiserror::Error;

use crate::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, ExactDeadlineError, ExactDeadlineReader, PluginArgs,
    PluginArgsParseError, PluginRegistrationStep, QemuAdvanceVirtualTimeDirectFn,
    QemuClockDeadlineFn, SynchronousIdleAdvance, SynchronousIdleAdvanceError,
    TimeControlRegistrationPlan,
};

/// QEMU capabilities captured at callback registration.
#[derive(Clone, Debug)]
pub struct PluginCallbackCapabilities {
    exact_deadline_reader: ExactDeadlineReader,
    synchronous_idle_advance: SynchronousIdleAdvance,
}

impl PluginCallbackCapabilities {
    /// Builds callback capabilities from required QEMU handles.
    #[must_use]
    pub const fn new(
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
    ) -> Self {
        Self {
            exact_deadline_reader,
            synchronous_idle_advance,
        }
    }

    /// Returns the exact-deadline reader required by the idle callback.
    #[must_use]
    pub const fn exact_deadline_reader(&self) -> &ExactDeadlineReader {
        &self.exact_deadline_reader
    }

    /// Returns the synchronous direct-advance handle required by the idle callback.
    #[must_use]
    pub const fn synchronous_idle_advance(&self) -> &SynchronousIdleAdvance {
        &self.synchronous_idle_advance
    }
}

/// Safe recorder for the fixed plugin registration path.
///
/// The recorder accepts only the canonical [`PluginRegistrationStep`] order. A
/// failed current step records a diagnostic and permanently blocks every later
/// step, matching the fail-loud registration contract from RFC-0010.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PluginRegistrationSequence {
    completed_steps: Vec<PluginRegistrationStep>,
    failure: Option<PluginRegistrationFailure>,
}

impl PluginRegistrationSequence {
    /// Returns a new empty registration sequence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the fixed registration order enforced by this recorder.
    #[must_use]
    pub const fn fixed_order() -> &'static [PluginRegistrationStep] {
        &CANONICAL_TIME_CONTROL_REGISTRATION_ORDER
    }

    /// Parses plugin arguments as the first registration step.
    ///
    /// On success, this records [`PluginRegistrationStep::ParseArguments`]. On
    /// parse failure, this records a failure at the parse step and returns a
    /// step-scoped diagnostic. No later registration step may be recorded after
    /// that failure.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when parsing fails or when
    /// the sequence is already past, complete, or failed before the parse step.
    pub fn parse_arguments(
        &mut self,
        raw: &str,
    ) -> Result<PluginArgs, PluginRegistrationSequenceError> {
        match PluginArgs::parse(raw) {
            Ok(args) => {
                self.record_step(PluginRegistrationStep::ParseArguments)?;
                Ok(args)
            }
            Err(source) => Err(self.fail_parse_arguments(source)),
        }
    }

    /// Records successful completion of one registration step.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when `step` is not the next
    /// canonical step, when registration has already failed, or when the full
    /// registration sequence is already complete.
    pub fn record_step(
        &mut self,
        step: PluginRegistrationStep,
    ) -> Result<(), PluginRegistrationSequenceError> {
        if step == PluginRegistrationStep::RegisterCallbacks {
            return Err(self.fail_step(
                PluginRegistrationStep::RegisterCallbacks,
                "exact deadline and synchronous idle-advance capabilities must be required before registering callbacks",
            ));
        }

        self.record_step_unchecked(step)
    }

    fn record_step_unchecked(
        &mut self,
        step: PluginRegistrationStep,
    ) -> Result<(), PluginRegistrationSequenceError> {
        if let Some(failure) = &self.failure {
            return Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: failure.step,
                blocked_step: step,
            });
        }

        let Some(expected_step) = self.next_step() else {
            return Err(PluginRegistrationSequenceError::AlreadyComplete { step });
        };

        if step != expected_step {
            return Err(self.poison_out_of_order(expected_step, step));
        }

        self.completed_steps.push(step);
        Ok(())
    }

    /// Records callback registration after requiring idle-time QEMU capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when
    /// `qemu_plugin_clock_deadline_ns` or
    /// `qemu_plugin_advance_virtual_time_direct` is unavailable, when the
    /// registration order is wrong, or when registration has already failed.
    pub fn register_callbacks_with_exact_deadline(
        &mut self,
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
        advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
    ) -> Result<PluginCallbackCapabilities, PluginRegistrationSequenceError> {
        let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
            .map_err(|source| self.fail_exact_deadline_capability(source))?;
        let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
            .map_err(|source| self.fail_synchronous_idle_advance_capability(source))?;
        self.record_step_unchecked(PluginRegistrationStep::RegisterCallbacks)?;
        Ok(PluginCallbackCapabilities::new(
            exact_deadline_reader,
            synchronous_idle_advance,
        ))
    }

    /// Records a fail-loud abort at the current registration step.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError::StepFailed`] for the newly
    /// recorded failure. Returns another sequencing error instead when `step` is
    /// not the current step, registration had already failed, or registration
    /// had already completed.
    pub fn fail_step(
        &mut self,
        step: PluginRegistrationStep,
        diagnostic: impl Into<String>,
    ) -> PluginRegistrationSequenceError {
        if let Some(failure) = &self.failure {
            return PluginRegistrationSequenceError::AfterFailure {
                failed_step: failure.step,
                blocked_step: step,
            };
        }

        let Some(expected_step) = self.next_step() else {
            return PluginRegistrationSequenceError::AlreadyComplete { step };
        };

        if step != expected_step {
            return self.poison_out_of_order(expected_step, step);
        }

        let failure = PluginRegistrationFailure {
            step,
            diagnostic: diagnostic.into(),
        };
        self.failure = Some(failure.clone());
        PluginRegistrationSequenceError::StepFailed { failure }
    }

    /// Finishes registration and returns a token permitting guest execution.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when registration failed or
    /// when at least one required step has not yet completed.
    pub fn finish(self) -> Result<PluginRegistrationReady, PluginRegistrationSequenceError> {
        if let Some(failure) = &self.failure {
            return Err(PluginRegistrationSequenceError::StepFailed {
                failure: failure.clone(),
            });
        }

        if let Some(next_step) = self.next_step() {
            return Err(PluginRegistrationSequenceError::IncompleteRegistration { next_step });
        }

        Ok(PluginRegistrationReady { _private: () })
    }

    /// Returns the completed registration steps.
    #[must_use]
    pub fn completed_steps(&self) -> &[PluginRegistrationStep] {
        &self.completed_steps
    }

    /// Returns the next required registration step.
    #[must_use]
    pub fn next_step(&self) -> Option<PluginRegistrationStep> {
        Self::fixed_order().get(self.completed_steps.len()).copied()
    }

    /// Returns the recorded failure, if any.
    #[must_use]
    pub const fn failure(&self) -> Option<&PluginRegistrationFailure> {
        self.failure.as_ref()
    }

    /// Returns `true` after the registration path has failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failure.is_some()
    }

    /// Returns `true` after every registration step has completed successfully.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failure.is_none() && self.completed_steps.len() == Self::fixed_order().len()
    }

    /// Validates that the time-control plan matches the registration sequence.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError::InvalidCanonicalOrder`] if the
    /// shared canonical plan no longer validates the time-control constraints.
    pub fn validate_canonical_plan() -> Result<(), PluginRegistrationSequenceError> {
        TimeControlRegistrationPlan::canonical()
            .validate()
            .map_err(|source| PluginRegistrationSequenceError::InvalidCanonicalOrder { source })
    }

    fn fail_parse_arguments(
        &mut self,
        source: PluginArgsParseError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::ParseArguments,
            format!("argument parsing failed: {source}"),
        )
    }

    fn fail_exact_deadline_capability(
        &mut self,
        source: ExactDeadlineError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::RegisterCallbacks,
            format!("exact deadline introspection failed: {source}"),
        )
    }

    fn fail_synchronous_idle_advance_capability(
        &mut self,
        source: SynchronousIdleAdvanceError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::RegisterCallbacks,
            format!("synchronous idle advance failed: {source}"),
        )
    }

    fn poison_out_of_order(
        &mut self,
        expected: PluginRegistrationStep,
        actual: PluginRegistrationStep,
    ) -> PluginRegistrationSequenceError {
        self.failure = Some(PluginRegistrationFailure {
            step: actual,
            diagnostic: format!("out-of-order registration step; expected {expected:?}"),
        });
        PluginRegistrationSequenceError::OutOfOrderStep { expected, actual }
    }
}

/// A fail-loud registration abort diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginRegistrationFailure {
    step: PluginRegistrationStep,
    diagnostic: String,
}

impl PluginRegistrationFailure {
    /// Returns the step that failed.
    #[must_use]
    pub const fn step(&self) -> PluginRegistrationStep {
        self.step
    }

    /// Returns the fail-loud diagnostic for the failed step.
    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// Proof that registration reached the first-instruction gate in order.
#[derive(Debug, PartialEq, Eq)]
pub struct PluginRegistrationReady {
    _private: (),
}

/// An error produced while sequencing plugin registration.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginRegistrationSequenceError {
    /// A step was attempted before its prerequisite step completed.
    #[error("plugin registration step {actual:?} is out of order; expected {expected:?}")]
    OutOfOrderStep {
        /// The required next step.
        expected: PluginRegistrationStep,
        /// The attempted step.
        actual: PluginRegistrationStep,
    },
    /// A step failed and registration must abort.
    #[error("plugin registration step {step:?} failed: {diagnostic}", step = .failure.step, diagnostic = .failure.diagnostic)]
    StepFailed {
        /// Failed step and diagnostic.
        failure: PluginRegistrationFailure,
    },
    /// A later step was attempted after an earlier failure.
    #[error("plugin registration step {blocked_step:?} blocked after failed step {failed_step:?}")]
    AfterFailure {
        /// The step that failed first.
        failed_step: PluginRegistrationStep,
        /// The later step that was refused.
        blocked_step: PluginRegistrationStep,
    },
    /// Another step was attempted after registration completed.
    #[error("plugin registration already completed before attempted step {step:?}")]
    AlreadyComplete {
        /// Step attempted after completion.
        step: PluginRegistrationStep,
    },
    /// Registration has not yet reached the first-instruction gate.
    #[error("plugin registration is incomplete; next step is {next_step:?}")]
    IncompleteRegistration {
        /// The next step that must complete.
        next_step: PluginRegistrationStep,
    },
    /// The shared canonical time-control order no longer validates.
    #[error("canonical plugin registration order is invalid")]
    InvalidCanonicalOrder {
        /// Underlying time-control ordering error.
        source: crate::TimeControlRegistrationError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_order_accepts_fixed_happy_path() {
        let mut sequence = PluginRegistrationSequence::new();

        record_fixed_sequence(&mut sequence);

        assert_eq!(
            sequence.completed_steps(),
            PluginRegistrationSequence::fixed_order()
        );
        assert!(sequence.is_complete());
        assert!(matches!(
            sequence.finish(),
            Ok(PluginRegistrationReady { .. })
        ));
    }

    #[test]
    fn registration_ready_token_consumes_sequence() {
        let mut sequence = PluginRegistrationSequence::new();
        record_fixed_sequence(&mut sequence);

        let ready = match sequence.finish() {
            Ok(ready) => ready,
            Err(error) => panic!("completed registration should finish: {error}"),
        };
        let _ownership = crate::PluginTimeControlOwnership::acquired_after_registration(ready);
    }

    #[test]
    fn registration_order_parse_step_uses_fail_closed_args() {
        let mut sequence = PluginRegistrationSequence::new();

        let args = match sequence.parse_arguments("simfd=3,slot=1") {
            Ok(args) => args,
            Err(error) => panic!("valid arguments should parse and record: {error}"),
        };

        assert_eq!(args.sim_fd(), 3);
        assert_eq!(args.slot(), 1);
        assert_eq!(
            sequence.completed_steps(),
            &[PluginRegistrationStep::ParseArguments]
        );

        let mut failed = PluginRegistrationSequence::new();
        let error = failed
            .parse_arguments("slot=0")
            .err()
            .unwrap_or_else(|| panic!("missing simfd should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected step-scoped parse failure, got {error:?}");
        };
        assert_eq!(failure.step(), PluginRegistrationStep::ParseArguments);
        assert!(
            failure
                .diagnostic()
                .contains("missing required plugin argument `simfd`")
        );
        assert!(failed.is_failed());
        assert_eq!(
            failed.record_step(PluginRegistrationStep::ControlHandshake),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::ParseArguments,
                blocked_step: PluginRegistrationStep::ControlHandshake,
            })
        );
    }

    #[test]
    fn registration_order_rejects_handshake_before_parse() {
        let mut sequence = PluginRegistrationSequence::new();

        assert_eq!(
            sequence.record_step(PluginRegistrationStep::ControlHandshake),
            Err(PluginRegistrationSequenceError::OutOfOrderStep {
                expected: PluginRegistrationStep::ParseArguments,
                actual: PluginRegistrationStep::ControlHandshake,
            })
        );
        assert!(sequence.completed_steps().is_empty());
        assert!(sequence.is_failed());
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::ParseArguments),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::ControlHandshake,
                blocked_step: PluginRegistrationStep::ParseArguments,
            })
        );
    }

    #[test]
    fn registration_order_aborts_without_later_steps_after_failure() {
        let mut sequence = PluginRegistrationSequence::new();
        if let Err(error) = sequence.record_step(PluginRegistrationStep::ParseArguments) {
            panic!("parse step should record: {error}");
        }

        let error = sequence.fail_step(PluginRegistrationStep::ControlHandshake, "closed socket");
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected handshake failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::ControlHandshake);
        assert_eq!(failure.diagnostic(), "closed socket");
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::RequestTimeControl),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::ControlHandshake,
                blocked_step: PluginRegistrationStep::RequestTimeControl,
            })
        );
        assert_eq!(
            sequence.completed_steps(),
            &[PluginRegistrationStep::ParseArguments]
        );
    }

    #[test]
    fn registration_order_requires_boot_barrier_before_first_instruction() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_setup_ack(&mut sequence);

        assert_eq!(
            sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction),
            Err(PluginRegistrationSequenceError::OutOfOrderStep {
                expected: PluginRegistrationStep::WaitBootBarrier,
                actual: PluginRegistrationStep::FirstVisibleInstruction,
            })
        );
    }

    #[test]
    fn registration_order_rejects_callback_registration_without_exact_deadline_capability() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);

        let error = sequence.record_step(PluginRegistrationStep::RegisterCallbacks);

        let Err(PluginRegistrationSequenceError::StepFailed { failure }) = error else {
            panic!("direct callback registration should fail, got {error:?}");
        };
        assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
        assert!(failure.diagnostic().contains("exact deadline"));
        assert!(failure.diagnostic().contains("synchronous idle-advance"));
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::SendSetupAck),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::RegisterCallbacks,
                blocked_step: PluginRegistrationStep::SendSetupAck,
            })
        );
    }

    #[test]
    fn registration_order_reuses_canonical_time_control_plan() {
        assert_eq!(
            PluginRegistrationSequence::fixed_order(),
            &CANONICAL_TIME_CONTROL_REGISTRATION_ORDER
        );
        assert_eq!(
            PluginRegistrationSequence::validate_canonical_plan(),
            Ok(())
        );
    }

    #[test]
    fn registration_order_records_callbacks_after_exact_deadline_capability_check() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);

        let capabilities = match sequence.register_callbacks_with_exact_deadline(
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
        ) {
            Ok(capabilities) => capabilities,
            Err(error) => panic!("exact deadline capability should register callbacks: {error}"),
        };

        assert_eq!(
            capabilities.exact_deadline_reader().read_next_deadline(),
            Ok(crate::ExactDeadlineReport::Armed { deadline_ns: 777 })
        );
        assert_eq!(
            sequence.completed_steps(),
            &[
                PluginRegistrationStep::ParseArguments,
                PluginRegistrationStep::ControlHandshake,
                PluginRegistrationStep::RequestTimeControl,
                PluginRegistrationStep::ReceiveSetup,
                PluginRegistrationStep::MapSharedMemory,
                PluginRegistrationStep::ArmWakeFd,
                PluginRegistrationStep::RegisterCallbacks,
            ]
        );
    }

    #[test]
    fn registration_order_fails_loud_when_exact_deadline_capability_missing() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);

        let error = sequence
            .register_callbacks_with_exact_deadline(None, Some(registration_test_direct_advance))
            .err()
            .unwrap_or_else(|| panic!("missing exact deadline capability should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected registration step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
        assert!(
            failure
                .diagnostic()
                .contains(crate::QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL)
        );
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::SendSetupAck),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::RegisterCallbacks,
                blocked_step: PluginRegistrationStep::SendSetupAck,
            })
        );
    }

    #[test]
    fn registration_order_fails_loud_when_synchronous_idle_advance_missing() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);

        let error = sequence
            .register_callbacks_with_exact_deadline(Some(registration_test_deadline), None)
            .err()
            .unwrap_or_else(|| panic!("missing synchronous idle advance should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected registration step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
        assert!(
            failure
                .diagnostic()
                .contains(crate::QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL)
        );
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::SendSetupAck),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::RegisterCallbacks,
                blocked_step: PluginRegistrationStep::SendSetupAck,
            })
        );
    }

    fn record_steps_through_wake_fd(sequence: &mut PluginRegistrationSequence) {
        for step in [
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
        ] {
            if let Err(error) = sequence.record_step(step) {
                panic!("prerequisite step {step:?} should record: {error}");
            }
        }
    }

    fn record_steps_through_setup_ack(sequence: &mut PluginRegistrationSequence) {
        record_steps_through_wake_fd(sequence);
        if let Err(error) = sequence.register_callbacks_with_exact_deadline(
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
        ) {
            panic!("exact deadline capability should register callbacks: {error}");
        }
        if let Err(error) = sequence.record_step(PluginRegistrationStep::SendSetupAck) {
            panic!("setup ack step should record: {error}");
        }
    }

    fn record_fixed_sequence(sequence: &mut PluginRegistrationSequence) {
        record_steps_through_setup_ack(sequence);
        for step in [
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        ] {
            if let Err(error) = sequence.record_step(step) {
                panic!("canonical step {step:?} should record: {error}");
            }
        }
    }

    extern "C" fn registration_test_deadline() -> i64 {
        777
    }

    extern "C" fn registration_test_direct_advance(_target_virtual_ns: i64) {}
}
