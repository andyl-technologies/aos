//! Fail-stop sequencing for QEMU plugin registration.
//!
//! The QEMU FFI entry point will eventually call into this module around each
//! side-effecting operation. Keeping the ordering state machine safe and
//! testable here ensures the registration path remains:
//!
//! ```text
//! parse -> handshake -> time control -> setup -> callbacks -> ready ack -> boot barrier -> guest code
//! ```

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;

use thiserror::Error;

#[cfg(unix)]
use crucible_protocol::ReceivedSetup;
use crucible_shmem::NodeSlot;

use crate::{
    BootBarrierError, BootBarrierRelease, CANONICAL_TIME_CONTROL_REGISTRATION_ORDER,
    CoverageCallback, CoverageCapabilities, CoverageError, CoverageRegistrationPlan,
    ExactDeadlineError, ExactDeadlineReader, PluginArgs, PluginArgsParseError, PluginBootBarrier,
    PluginControlHandshake, PluginCoverage, PluginHandshakeError, PluginReadySetupAck,
    PluginRegistrationStep, QemuAdvanceVirtualTimeDirectFn, QemuClockDeadlineFn,
    SynchronousIdleAdvance, SynchronousIdleAdvanceError, TimeControlRegistrationPlan,
    perform_plugin_handshake,
};
#[cfg(unix)]
use crate::{
    PluginSetupCompletion, PluginSetupError, PluginSetupFailureStage,
    prepare_setup_completion as plugin_prepare_setup_completion,
    receive_setup_with_descriptors as plugin_receive_setup_with_descriptors,
    send_ready_setup_ack as plugin_send_ready_setup_ack,
};

/// QEMU capabilities captured at callback registration.
#[derive(Clone, Debug)]
pub struct PluginCallbackCapabilities {
    exact_deadline_reader: ExactDeadlineReader,
    synchronous_idle_advance: SynchronousIdleAdvance,
    coverage_registration_plan: CoverageRegistrationPlan,
    coverage_callback: Option<CoverageCallback>,
}

impl PluginCallbackCapabilities {
    /// Builds callback capabilities from required QEMU handles.
    #[must_use]
    const fn new(
        exact_deadline_reader: ExactDeadlineReader,
        synchronous_idle_advance: SynchronousIdleAdvance,
        coverage_registration_plan: CoverageRegistrationPlan,
        coverage_callback: Option<CoverageCallback>,
    ) -> Self {
        Self {
            exact_deadline_reader,
            synchronous_idle_advance,
            coverage_registration_plan,
            coverage_callback,
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

    /// Returns the registration-time coverage decision.
    #[must_use]
    pub const fn coverage_registration_plan(&self) -> CoverageRegistrationPlan {
        self.coverage_registration_plan
    }

    /// Returns the coverage callback token when coverage was enabled.
    #[must_use]
    pub const fn coverage_callback(&self) -> Option<CoverageCallback> {
        self.coverage_callback
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

    /// Performs and records the control-socket `Hello`/`HelloAck` handshake.
    ///
    /// The registration sequence must already have parsed arguments, and no
    /// control-socket bytes are written unless [`PluginRegistrationStep::ControlHandshake`]
    /// is the next expected step.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the sequence is not at
    /// the handshake step, when the protocol handshake fails, when versions do
    /// not match, when the assigned slot is outside `node_count`, or when the
    /// handshake slot disagrees with the launch argument.
    pub fn perform_control_handshake<S>(
        &mut self,
        stream: &mut S,
        args: &PluginArgs,
    ) -> Result<PluginControlHandshake, PluginRegistrationSequenceError>
    where
        S: Read + Write,
    {
        self.ensure_next_step(PluginRegistrationStep::ControlHandshake)?;
        let handshake = perform_plugin_handshake(stream, args)
            .map_err(|source| self.fail_control_handshake(source))?;
        self.record_step_unchecked(PluginRegistrationStep::ControlHandshake)?;
        Ok(handshake)
    }

    /// Receives and records the host `Setup` frame and its two descriptors.
    ///
    /// The sequence must already have acquired QEMU time control. The method
    /// checks the registration step before reading the control socket, so an
    /// out-of-order call cannot consume setup bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when setup receive is out of
    /// order, the socket closes, the frame is malformed, or the frame carries
    /// anything other than exactly two `SCM_RIGHTS` descriptors.
    #[cfg(unix)]
    pub fn receive_setup_with_descriptors<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<ReceivedSetup, PluginRegistrationSequenceError>
    where
        S: AsRawFd + Write,
    {
        self.ensure_next_step(PluginRegistrationStep::ReceiveSetup)?;
        let setup = plugin_receive_setup_with_descriptors(stream)
            .map_err(|source| self.fail_setup_receive(source))?;
        self.record_step_unchecked(PluginRegistrationStep::ReceiveSetup)?;
        Ok(setup)
    }

    /// Maps shared memory, validates setup ABI state, and arms the wake fd.
    ///
    /// On success this records both [`PluginRegistrationStep::MapSharedMemory`]
    /// and [`PluginRegistrationStep::ArmWakeFd`]. On failure it keeps the
    /// failure attached to the setup milestone that actually failed.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when setup preparation is
    /// out of order, mapping or validation fails, the mapped header disagrees
    /// with the negotiated handshake assignment, the wake fd cannot be armed, or
    /// the nonzero failure `SetupAck` cannot be sent.
    #[cfg(unix)]
    pub fn prepare_setup_completion<W>(
        &mut self,
        writer: &mut W,
        setup: ReceivedSetup,
        handshake: PluginControlHandshake,
    ) -> Result<PluginSetupCompletion, PluginRegistrationSequenceError>
    where
        W: Write,
    {
        self.ensure_next_step(PluginRegistrationStep::MapSharedMemory)?;
        let completion = plugin_prepare_setup_completion(writer, setup, handshake)
            .map_err(|source| self.fail_setup_preparation(source))?;
        self.record_step_unchecked(PluginRegistrationStep::MapSharedMemory)?;
        self.record_step_unchecked(PluginRegistrationStep::ArmWakeFd)?;
        Ok(completion)
    }

    /// Sends ready `SetupAck(0)` only after callback registration.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the sequence has not
    /// reached the ready-ack step or when the acknowledgement cannot be written.
    #[cfg(unix)]
    pub fn send_ready_setup_ack<W>(
        &mut self,
        writer: &mut W,
        completion: &PluginSetupCompletion,
        callbacks: &PluginCallbackCapabilities,
    ) -> Result<PluginReadySetupAck, PluginRegistrationSequenceError>
    where
        W: Write,
    {
        self.ensure_next_step(PluginRegistrationStep::SendSetupAck)?;
        let setup_ack = plugin_send_ready_setup_ack(writer, completion, callbacks)
            .map_err(|source| self.fail_ready_setup_ack(source))?;
        self.record_step_unchecked(PluginRegistrationStep::SendSetupAck)?;
        Ok(setup_ack)
    }

    /// Waits for the scheduler to publish the initial boot ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the sequence has not
    /// reached the boot-barrier step, the shared-memory wait precondition cannot
    /// be published, or the non-private futex wait fails.
    pub fn wait_boot_barrier(
        &mut self,
        setup_ack: PluginReadySetupAck,
        slot: &NodeSlot,
        icount_shift: u8,
    ) -> Result<BootBarrierRelease, PluginRegistrationSequenceError> {
        self.ensure_next_step(PluginRegistrationStep::WaitBootBarrier)?;
        let release = PluginBootBarrier::wait(setup_ack, slot, icount_shift)
            .map_err(|source| self.fail_boot_barrier(source))?;
        self.record_step_unchecked(PluginRegistrationStep::WaitBootBarrier)?;
        Ok(release)
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
        if let Some(failure) = &self.failure {
            return Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: failure.step,
                blocked_step: step,
            });
        }
        if step == PluginRegistrationStep::RegisterCallbacks {
            return Err(self.fail_step(
                PluginRegistrationStep::RegisterCallbacks,
                "exact deadline and synchronous idle-advance capabilities, plus optional coverage callback planning, must be required before registering callbacks",
            ));
        }
        if step == PluginRegistrationStep::SendSetupAck {
            return Err(self.fail_step(
                PluginRegistrationStep::SendSetupAck,
                "ready SetupAck(0) must be written with setup completion and callback tokens",
            ));
        }
        if step == PluginRegistrationStep::WaitBootBarrier {
            return Err(self.fail_step(
                PluginRegistrationStep::WaitBootBarrier,
                "the boot barrier must wait on the shared-memory wake_signal futex before guest code",
            ));
        }

        self.record_step_unchecked(step)
    }

    fn record_step_unchecked(
        &mut self,
        step: PluginRegistrationStep,
    ) -> Result<(), PluginRegistrationSequenceError> {
        self.ensure_next_step(step)?;
        self.completed_steps.push(step);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_test_ready_setup_ack(
        &mut self,
    ) -> Result<PluginReadySetupAck, PluginRegistrationSequenceError> {
        self.ensure_next_step(PluginRegistrationStep::SendSetupAck)?;
        self.record_step_unchecked(PluginRegistrationStep::SendSetupAck)?;
        Ok(PluginReadySetupAck::test_acknowledged())
    }

    fn ensure_next_step(
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

        Ok(())
    }

    /// Records callback registration after requiring idle-time QEMU capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when
    /// `qemu_plugin_clock_deadline_ns` or
    /// `qemu_plugin_advance_virtual_time_direct` is unavailable, when
    /// `coverage=on` but QEMU's TCG-exec callback export is unavailable, when
    /// the registration order is wrong, or when registration has already
    /// failed.
    pub fn register_callbacks_with_exact_deadline(
        &mut self,
        args: &PluginArgs,
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
        advance_virtual_time_direct: Option<QemuAdvanceVirtualTimeDirectFn>,
        coverage_capabilities: CoverageCapabilities,
    ) -> Result<PluginCallbackCapabilities, PluginRegistrationSequenceError> {
        let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
            .map_err(|source| self.fail_exact_deadline_capability(source))?;
        let synchronous_idle_advance = SynchronousIdleAdvance::require(advance_virtual_time_direct)
            .map_err(|source| self.fail_synchronous_idle_advance_capability(source))?;
        let coverage_registration_plan = PluginCoverage::with_default_map(args.coverage())
            .registration_plan(coverage_capabilities)
            .map_err(|source| self.fail_coverage_capability(source))?;
        let coverage_callback = match coverage_registration_plan {
            CoverageRegistrationPlan::Disabled => None,
            CoverageRegistrationPlan::Install { .. } => Some(
                coverage_registration_plan
                    .require_callback()
                    .map_err(|source| self.fail_coverage_capability(source))?,
            ),
        };
        self.record_step_unchecked(PluginRegistrationStep::RegisterCallbacks)?;
        Ok(PluginCallbackCapabilities::new(
            exact_deadline_reader,
            synchronous_idle_advance,
            coverage_registration_plan,
            coverage_callback,
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

    fn fail_control_handshake(
        &mut self,
        source: PluginHandshakeError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::ControlHandshake,
            format!("control handshake failed: {source}"),
        )
    }

    #[cfg(unix)]
    fn fail_setup_receive(&mut self, source: PluginSetupError) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::ReceiveSetup,
            format!("setup descriptor receive failed: {source}"),
        )
    }

    #[cfg(unix)]
    fn fail_setup_preparation(
        &mut self,
        source: PluginSetupError,
    ) -> PluginRegistrationSequenceError {
        let step = setup_error_registration_step(&source);
        if step == PluginRegistrationStep::ArmWakeFd
            && self.next_step() == Some(PluginRegistrationStep::MapSharedMemory)
        {
            self.completed_steps
                .push(PluginRegistrationStep::MapSharedMemory);
        }
        self.fail_step(step, format!("setup completion failed: {source}"))
    }

    #[cfg(unix)]
    fn fail_ready_setup_ack(
        &mut self,
        source: PluginSetupError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::SendSetupAck,
            format!("ready setup acknowledgement failed: {source}"),
        )
    }

    fn fail_boot_barrier(&mut self, source: BootBarrierError) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::WaitBootBarrier,
            format!("boot barrier wait failed: {source}"),
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

    fn fail_coverage_capability(
        &mut self,
        source: CoverageError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::RegisterCallbacks,
            format!("coverage callback registration failed: {source}"),
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

#[cfg(unix)]
const fn setup_error_registration_step(source: &PluginSetupError) -> PluginRegistrationStep {
    match source {
        PluginSetupError::ReceiveSetup { .. } => PluginRegistrationStep::ReceiveSetup,
        PluginSetupError::MapRegion { .. }
        | PluginSetupError::ValidateRegion { .. }
        | PluginSetupError::NodeCountMismatch { .. }
        | PluginSetupError::SlotOutsideRegionNodeCount { .. } => {
            PluginRegistrationStep::MapSharedMemory
        }
        PluginSetupError::ArmWakeFd { .. } => PluginRegistrationStep::ArmWakeFd,
        PluginSetupError::SendReadyAck { .. } => PluginRegistrationStep::SendSetupAck,
        PluginSetupError::SendFailureAck { stage, .. } => match stage {
            PluginSetupFailureStage::ReceiveSetup => PluginRegistrationStep::ReceiveSetup,
            PluginSetupFailureStage::MapRegion
            | PluginSetupFailureStage::ValidateRegion
            | PluginSetupFailureStage::CrossCheckSlot => PluginRegistrationStep::MapSharedMemory,
            PluginSetupFailureStage::ArmWakeFd => PluginRegistrationStep::ArmWakeFd,
        },
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

    use std::io::{Cursor, Read, Write};

    use crucible_protocol::{CONTROL_PROTOCOL_VERSION, HostMsg, control_encode_host_msg};
    use crucible_shmem::{ABI_VERSION, KIND_VM, NodeSlot, authorize_advance_ceiling};

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
    fn registration_order_performs_control_handshake_after_parse() {
        let mut sequence = PluginRegistrationSequence::new();
        let args = sequence
            .parse_arguments("simfd=3,slot=1")
            .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
        let mut io = handshake_io(1, 4);

        let handshake = sequence
            .perform_control_handshake(&mut io, &args)
            .unwrap_or_else(|error| panic!("handshake should succeed: {error}"));

        assert_eq!(handshake.proto_version(), CONTROL_PROTOCOL_VERSION);
        assert_eq!(handshake.abi_version(), ABI_VERSION);
        assert_eq!(handshake.slot_index(), 1);
        assert_eq!(handshake.launch_slot(), 1);
        assert_eq!(handshake.node_count(), 4);
        assert!(!io.written().is_empty());
        assert_eq!(io.flush_count(), 1);
        assert_eq!(
            sequence.completed_steps(),
            &[
                PluginRegistrationStep::ParseArguments,
                PluginRegistrationStep::ControlHandshake,
            ]
        );
    }

    #[test]
    fn registration_order_rejects_control_handshake_before_parse_without_io() {
        let mut sequence = PluginRegistrationSequence::new();
        let args = registration_args("simfd=3,slot=0");
        let mut io = handshake_io(0, 1);

        assert_eq!(
            sequence.perform_control_handshake(&mut io, &args),
            Err(PluginRegistrationSequenceError::OutOfOrderStep {
                expected: PluginRegistrationStep::ParseArguments,
                actual: PluginRegistrationStep::ControlHandshake,
            })
        );
        assert!(io.written().is_empty());
        assert_eq!(io.flush_count(), 0);
    }

    #[test]
    fn registration_order_fails_loud_when_handshake_slot_disagrees_with_launch_args() {
        let mut sequence = PluginRegistrationSequence::new();
        let args = sequence
            .parse_arguments("simfd=3,slot=0")
            .unwrap_or_else(|error| panic!("valid arguments should parse: {error}"));
        let mut io = handshake_io(1, 2);

        let error = sequence
            .perform_control_handshake(&mut io, &args)
            .err()
            .unwrap_or_else(|| panic!("slot mismatch should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::ControlHandshake);
        assert!(failure.diagnostic().contains("launch slot 0"));
        assert!(failure.diagnostic().contains("handshake slot 1"));
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::RequestTimeControl),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::ControlHandshake,
                blocked_step: PluginRegistrationStep::RequestTimeControl,
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
        let _setup_ack = record_steps_through_setup_ack(&mut sequence);

        assert_eq!(
            sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction),
            Err(PluginRegistrationSequenceError::OutOfOrderStep {
                expected: PluginRegistrationStep::WaitBootBarrier,
                actual: PluginRegistrationStep::FirstVisibleInstruction,
            })
        );
    }

    #[test]
    fn registration_order_requires_boot_barrier_wait_helper() {
        let mut sequence = PluginRegistrationSequence::new();
        let _setup_ack = record_steps_through_setup_ack(&mut sequence);

        let error = sequence
            .record_step(PluginRegistrationStep::WaitBootBarrier)
            .err()
            .unwrap_or_else(|| panic!("direct boot-barrier record should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected boot-barrier step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::WaitBootBarrier);
        assert!(failure.diagnostic().contains("wake_signal futex"));
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::WaitBootBarrier,
                blocked_step: PluginRegistrationStep::FirstVisibleInstruction,
            })
        );
    }

    #[test]
    fn registration_order_waits_boot_barrier_before_first_instruction() {
        let mut sequence = PluginRegistrationSequence::new();
        let setup_ack = record_steps_through_setup_ack(&mut sequence);
        let slot = boot_barrier_slot(3);

        let release = sequence
            .wait_boot_barrier(setup_ack, &slot, 0)
            .unwrap_or_else(|error| panic!("boot barrier should release: {error}"));

        assert_eq!(
            release.first_guest_icount(),
            crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT
        );
        assert_eq!(release.released_ceiling(), 3);
        if let Err(error) = sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction) {
            panic!("first instruction sentinel should record after boot barrier: {error}");
        }
        assert_eq!(
            sequence.completed_steps(),
            PluginRegistrationSequence::fixed_order()
        );
    }

    #[test]
    fn registration_order_requires_ready_setup_ack_helper() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);
        let args = registration_args("simfd=3,slot=0");
        sequence
            .register_callbacks_with_exact_deadline(
                &args,
                Some(registration_test_deadline),
                Some(registration_test_direct_advance),
                CoverageCapabilities::none(),
            )
            .unwrap_or_else(|error| panic!("exact deadline capability should register: {error}"));

        let error = sequence
            .record_step(PluginRegistrationStep::SendSetupAck)
            .err()
            .unwrap_or_else(|| panic!("direct ready-ack record should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected ready-ack step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::SendSetupAck);
        assert!(failure.diagnostic().contains("SetupAck(0)"));
        assert!(failure.diagnostic().contains("callback tokens"));
        assert_eq!(
            sequence.record_step(PluginRegistrationStep::WaitBootBarrier),
            Err(PluginRegistrationSequenceError::AfterFailure {
                failed_step: PluginRegistrationStep::SendSetupAck,
                blocked_step: PluginRegistrationStep::WaitBootBarrier,
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
        let args = registration_args("simfd=3,slot=0");

        let capabilities = match sequence.register_callbacks_with_exact_deadline(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        ) {
            Ok(capabilities) => capabilities,
            Err(error) => panic!("exact deadline capability should register callbacks: {error}"),
        };

        assert_eq!(
            capabilities.exact_deadline_reader().read_next_deadline(),
            Ok(crate::ExactDeadlineReport::Armed { deadline_ns: 777 })
        );
        assert_eq!(
            capabilities.coverage_registration_plan(),
            CoverageRegistrationPlan::Disabled
        );
        assert_eq!(capabilities.coverage_callback(), None);
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
        let args = registration_args("simfd=3,slot=0");

        let error = sequence
            .register_callbacks_with_exact_deadline(
                &args,
                None,
                Some(registration_test_direct_advance),
                CoverageCapabilities::none(),
            )
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
        let args = registration_args("simfd=3,slot=0");

        let error = sequence
            .register_callbacks_with_exact_deadline(
                &args,
                Some(registration_test_deadline),
                None,
                CoverageCapabilities::none(),
            )
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

    #[test]
    fn registration_coverage_off_installs_no_callback_without_capability() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);
        let args = registration_args("simfd=3,slot=0,coverage=off");

        let capabilities = sequence
            .register_callbacks_with_exact_deadline(
                &args,
                Some(registration_test_deadline),
                Some(registration_test_direct_advance),
                CoverageCapabilities::none(),
            )
            .unwrap_or_else(|error| panic!("coverage off should not need TCG exec: {error}"));

        assert_eq!(
            capabilities.coverage_registration_plan(),
            CoverageRegistrationPlan::Disabled
        );
        assert!(
            !capabilities
                .coverage_registration_plan()
                .installs_callback()
        );
        assert_eq!(capabilities.coverage_callback(), None);
    }

    #[test]
    fn registration_coverage_on_requires_tcg_exec_callback_capability() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);
        let args = registration_args("simfd=3,slot=0,coverage=on");

        let error = sequence
            .register_callbacks_with_exact_deadline(
                &args,
                Some(registration_test_deadline),
                Some(registration_test_direct_advance),
                CoverageCapabilities::none(),
            )
            .err()
            .unwrap_or_else(|| panic!("coverage on without TCG exec should fail"));
        let PluginRegistrationSequenceError::StepFailed { failure } = error else {
            panic!("expected registration step failure, got {error:?}");
        };

        assert_eq!(failure.step(), PluginRegistrationStep::RegisterCallbacks);
        assert!(
            failure
                .diagnostic()
                .contains(crate::QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL)
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
    fn registration_coverage_on_installs_tcg_exec_callback_token() {
        let mut sequence = PluginRegistrationSequence::new();
        record_steps_through_wake_fd(&mut sequence);
        let args = registration_args("simfd=3,slot=0,coverage=on");

        let capabilities = sequence
            .register_callbacks_with_exact_deadline(
                &args,
                Some(registration_test_deadline),
                Some(registration_test_direct_advance),
                CoverageCapabilities::tcg_exec(),
            )
            .unwrap_or_else(|error| panic!("coverage on should register TCG exec: {error}"));

        assert_eq!(
            capabilities.coverage_registration_plan(),
            CoverageRegistrationPlan::Install {
                map_entries: crate::DEFAULT_COVERAGE_MAP_ENTRIES,
            }
        );
        assert!(
            capabilities
                .coverage_registration_plan()
                .installs_callback()
        );
        assert_eq!(
            capabilities
                .coverage_callback()
                .map(CoverageCallback::map_entries),
            Some(crate::DEFAULT_COVERAGE_MAP_ENTRIES)
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

    fn record_steps_through_setup_ack(
        sequence: &mut PluginRegistrationSequence,
    ) -> PluginReadySetupAck {
        record_steps_through_wake_fd(sequence);
        let args = registration_args("simfd=3,slot=0");
        if let Err(error) = sequence.register_callbacks_with_exact_deadline(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        ) {
            panic!("exact deadline capability should register callbacks: {error}");
        }
        sequence
            .record_test_ready_setup_ack()
            .unwrap_or_else(|error| panic!("setup ack step should record: {error}"))
    }

    fn record_fixed_sequence(sequence: &mut PluginRegistrationSequence) {
        let setup_ack = record_steps_through_setup_ack(sequence);
        let slot = boot_barrier_slot(2);
        if let Err(error) = sequence.wait_boot_barrier(setup_ack, &slot, 0) {
            panic!("boot barrier should release: {error}");
        }
        if let Err(error) = sequence.record_step(PluginRegistrationStep::FirstVisibleInstruction) {
            panic!("canonical first-instruction step should record: {error}");
        }
    }

    extern "C" fn registration_test_deadline() -> i64 {
        777
    }

    extern "C" fn registration_test_direct_advance(_target_virtual_ns: i64) {}

    fn registration_args(raw: &str) -> PluginArgs {
        PluginArgs::parse(raw).unwrap_or_else(|error| panic!("test args should parse: {error}"))
    }

    fn boot_barrier_slot(max_advance_icount: u64) -> NodeSlot {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, max_advance_icount, None)
            .unwrap_or_else(|error| panic!("boot barrier ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("boot barrier ceiling should publish: {error}"));
        slot
    }

    fn handshake_io(slot_index: u32, node_count: u32) -> ScriptedIo {
        ScriptedIo::from_input(control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index,
            node_count,
        }))
    }

    struct ScriptedIo {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        flush_count: usize,
    }

    impl ScriptedIo {
        fn from_input(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
                flush_count: 0,
            }
        }

        fn written(&self) -> Vec<u8> {
            self.output.clone()
        }

        const fn flush_count(&self) -> usize {
            self.flush_count
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }
    }
}
