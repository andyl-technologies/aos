//! Fail-stop sequencing for QEMU plugin registration.
//!
//! The QEMU FFI entry point uses it around each side effect to preserve:
//! ```text
//! parse -> handshake -> time control -> setup -> callbacks -> ready ack -> boot barrier -> guest code
//! ```

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;

use thiserror::Error;

#[cfg(unix)]
use crucible_protocol::{ControlLifecycleStream, ReceivedSetup};
use crucible_shmem::NodeSlot;

use crate::{
    BootBarrierError, BootBarrierRelease, CANONICAL_TIME_CONTROL_REGISTRATION_ORDER,
    CoverageCallback, CoverageCapabilities, CoverageError, CoverageRegistrationPlan,
    ExactDeadlineError, ExactDeadlineReader, PluginArgs, PluginArgsParseError, PluginBootBarrier,
    PluginControlHandshake, PluginCoverage, PluginHandshakeError, PluginReadySetupAck,
    PluginRegistrationStep, QemuAdvanceTimeNsFn, QemuClockDeadlineFn, QueuedIdleAdvance,
    QueuedIdleAdvanceError, RequiredOwnedCallbacksRegistered, TimeControlRegistrationPlan,
    perform_plugin_handshake,
};
#[cfg(unix)]
use crate::{
    PluginSetupCompletion, PluginSetupError, PluginSetupFailureStage,
    prepare_setup_completion as plugin_prepare_setup_completion,
    receive_setup_with_descriptors as plugin_receive_setup_with_descriptors,
    send_ready_setup_ack as plugin_send_ready_setup_ack,
};
#[cfg(unix)]
use crate::{plugin_handshake_config, validate_plugin_handshake};

mod live;

/// QEMU capabilities captured at callback registration.
#[derive(Clone, Debug)]
pub struct PluginCallbackCapabilities {
    exact_deadline_reader: ExactDeadlineReader,
    queued_idle_advance: QueuedIdleAdvance,
    coverage_registration_plan: CoverageRegistrationPlan,
    coverage_callback: Option<CoverageCallback>,
}

impl PluginCallbackCapabilities {
    /// Builds callback capabilities from required QEMU handles.
    #[must_use]
    const fn new(
        exact_deadline_reader: ExactDeadlineReader,
        queued_idle_advance: QueuedIdleAdvance,
        coverage_registration_plan: CoverageRegistrationPlan,
        coverage_callback: Option<CoverageCallback>,
    ) -> Self {
        Self {
            exact_deadline_reader,
            queued_idle_advance,
            coverage_registration_plan,
            coverage_callback,
        }
    }

    /// Returns the exact-deadline reader required by the idle callback.
    #[must_use]
    pub const fn exact_deadline_reader(&self) -> &ExactDeadlineReader {
        &self.exact_deadline_reader
    }

    /// Returns the queued idle-advance handle required by the idle callback.
    #[must_use]
    pub const fn queued_idle_advance(&self) -> &QueuedIdleAdvance {
        &self.queued_idle_advance
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

    /// Performs the plugin handshake through the lifecycle-aware control stream.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the sequence is out of
    /// order, lifecycle-aware frame I/O fails, or the negotiated slot does not
    /// match the launch arguments.
    #[cfg(unix)]
    pub fn perform_control_handshake_lifecycle<S>(
        &mut self,
        control: &mut ControlLifecycleStream<S>,
        args: &PluginArgs,
    ) -> Result<PluginControlHandshake, PluginRegistrationSequenceError>
    where
        S: Read + Write,
    {
        self.ensure_next_step(PluginRegistrationStep::ControlHandshake)?;
        let negotiated = control
            .plugin_start_handshake(plugin_handshake_config())
            .map_err(|source| {
                self.fail_step(
                    PluginRegistrationStep::ControlHandshake,
                    format!("lifecycle-aware control handshake failed: {source}"),
                )
            })?;
        let handshake = validate_plugin_handshake(args, negotiated)
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

    /// Receives setup descriptors through the lifecycle-aware control stream.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when setup receive is out of
    /// order or the lifecycle-aware descriptor handoff fails.
    #[cfg(unix)]
    pub fn receive_setup_with_descriptors_lifecycle<S>(
        &mut self,
        control: &mut ControlLifecycleStream<S>,
    ) -> Result<ReceivedSetup, PluginRegistrationSequenceError>
    where
        S: AsRawFd + Write,
    {
        self.ensure_next_step(PluginRegistrationStep::ReceiveSetup)?;
        let setup = match control.plugin_recv_setup_with_descriptors() {
            Ok(setup) => setup,
            Err(source) => {
                let acknowledgement = control.plugin_send_setup_failure_ack();
                let diagnostic = match acknowledgement {
                    Ok(()) => format!("lifecycle-aware setup descriptor receive failed: {source}"),
                    Err(ack_source) => format!(
                        "lifecycle-aware setup descriptor receive failed: {source}; failure acknowledgement also failed: {ack_source}"
                    ),
                };
                return Err(self.fail_step(PluginRegistrationStep::ReceiveSetup, diagnostic));
            }
        };
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
        callbacks: &PluginCallbackCapabilities,
        owned_callbacks: &RequiredOwnedCallbacksRegistered,
    ) -> Result<PluginReadySetupAck, PluginRegistrationSequenceError>
    where
        W: Write,
    {
        self.ensure_next_step(PluginRegistrationStep::SendSetupAck)?;
        let setup_ack = plugin_send_ready_setup_ack(writer, callbacks, owned_callbacks)
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
                "exact deadline and queued idle-advance capabilities, plus optional coverage callback planning, must be required before registering callbacks",
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
    /// `qemu_plugin_advance_time_ns` is unavailable, when
    /// `coverage=on` but QEMU's stock TB translation/execution APIs are unavailable, when
    /// the registration order is wrong, or when registration has already
    /// failed.
    pub fn register_callbacks_with_exact_deadline(
        &mut self,
        plugin_id: crate::QemuPluginId,
        args: &PluginArgs,
        owned_callbacks: &mut RequiredOwnedCallbacksRegistered,
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
        advance_time_ns: Option<QemuAdvanceTimeNsFn>,
        coverage_capabilities: CoverageCapabilities,
    ) -> Result<PluginCallbackCapabilities, PluginRegistrationSequenceError> {
        self.register_callbacks_with_exact_deadline_inner(
            Some((plugin_id, owned_callbacks)),
            args,
            clock_deadline_ns,
            advance_time_ns,
            coverage_capabilities,
        )
    }

    #[cfg(test)]
    /// Registers the modeled callback capabilities without a live QEMU owner.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRegistrationSequenceError`] when the registration step
    /// is out of order or any required callback capability is absent.
    pub(crate) fn register_callbacks_for_test(
        &mut self,
        args: &PluginArgs,
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
        advance_time_ns: Option<QemuAdvanceTimeNsFn>,
        coverage_capabilities: CoverageCapabilities,
    ) -> Result<PluginCallbackCapabilities, PluginRegistrationSequenceError> {
        self.register_callbacks_with_exact_deadline_inner(
            None,
            args,
            clock_deadline_ns,
            advance_time_ns,
            coverage_capabilities,
        )
    }

    fn register_callbacks_with_exact_deadline_inner(
        &mut self,
        live_owner: Option<(crate::QemuPluginId, &mut RequiredOwnedCallbacksRegistered)>,
        args: &PluginArgs,
        clock_deadline_ns: Option<QemuClockDeadlineFn>,
        advance_time_ns: Option<QemuAdvanceTimeNsFn>,
        coverage_capabilities: CoverageCapabilities,
    ) -> Result<PluginCallbackCapabilities, PluginRegistrationSequenceError> {
        let exact_deadline_reader = ExactDeadlineReader::require(clock_deadline_ns)
            .map_err(|source| self.fail_exact_deadline_capability(source))?;
        let queued_idle_advance = QueuedIdleAdvance::require(advance_time_ns)
            .map_err(|source| self.fail_queued_idle_advance_capability(source))?;
        let coverage_registration_plan = PluginCoverage::with_default_map(args.coverage())
            .registration_plan(coverage_capabilities)
            .map_err(|source| self.fail_coverage_capability(source))?;
        let coverage_callback = match coverage_registration_plan {
            CoverageRegistrationPlan::Disabled => None,
            CoverageRegistrationPlan::Install { .. } => {
                let callback = coverage_registration_plan
                    .require_callback()
                    .map_err(|source| self.fail_coverage_capability(source))?;
                if let Some((plugin_id, owned_callbacks)) = live_owner {
                    let Some(apis) = coverage_capabilities.basic_block_apis() else {
                        return Err(self.fail_coverage_capability(
                            CoverageError::CapabilityUnavailable {
                                symbol: crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
                            },
                        ));
                    };
                    owned_callbacks
                        .register_basic_block_coverage(plugin_id, args.slot(), callback, apis)
                        .map_err(|source| self.fail_coverage_capability(source))?;
                }
                Some(callback)
            }
        };
        self.record_step_unchecked(PluginRegistrationStep::RegisterCallbacks)?;
        Ok(PluginCallbackCapabilities::new(
            exact_deadline_reader,
            queued_idle_advance,
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

    fn fail_queued_idle_advance_capability(
        &mut self,
        source: QueuedIdleAdvanceError,
    ) -> PluginRegistrationSequenceError {
        self.fail_step(
            PluginRegistrationStep::RegisterCallbacks,
            format!("queued idle advance failed: {source}"),
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
        PluginSetupError::ArmWakeFd { .. } | PluginSetupError::RegisterWakeFd { .. } => {
            PluginRegistrationStep::ArmWakeFd
        }
        PluginSetupError::WakeFdNotRegistered | PluginSetupError::SendReadyAck { .. } => {
            PluginRegistrationStep::SendSetupAck
        }
        PluginSetupError::SendFailureAck { stage, .. } => match stage {
            PluginSetupFailureStage::ReceiveSetup => PluginRegistrationStep::ReceiveSetup,
            PluginSetupFailureStage::MapRegion
            | PluginSetupFailureStage::ValidateRegion
            | PluginSetupFailureStage::CrossCheckSlot => PluginRegistrationStep::MapSharedMemory,
            PluginSetupFailureStage::ArmWakeFd | PluginSetupFailureStage::RegisterWakeFd => {
                PluginRegistrationStep::ArmWakeFd
            }
            PluginSetupFailureStage::RegisterCallbacks => PluginRegistrationStep::RegisterCallbacks,
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
mod tests;
