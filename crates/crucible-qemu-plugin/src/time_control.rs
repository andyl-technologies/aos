//! Plugin time-control registration order.
//!
//! The QEMU plugin ABI entry point will eventually execute this sequence while
//! holding raw QEMU handles. This module keeps the ordering contract in safe
//! Rust so the launch and harness layers can test the invariant before the FFI
//! body exists.

use std::collections::BTreeSet;

use thiserror::Error;

/// The canonical registration steps that protect virtual time before guest code runs.
pub const CANONICAL_TIME_CONTROL_REGISTRATION_ORDER: [PluginRegistrationStep; 10] = [
    PluginRegistrationStep::ParseArguments,
    PluginRegistrationStep::ControlHandshake,
    PluginRegistrationStep::RequestTimeControl,
    PluginRegistrationStep::ReceiveSetup,
    PluginRegistrationStep::MapSharedMemory,
    PluginRegistrationStep::ArmWakeFd,
    PluginRegistrationStep::RegisterCallbacks,
    PluginRegistrationStep::SendSetupAck,
    PluginRegistrationStep::WaitBootBarrier,
    PluginRegistrationStep::FirstVisibleInstruction,
];

/// A single milestone in the QEMU plugin registration path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginRegistrationStep {
    /// Parses plugin arguments before any side effect.
    ParseArguments,
    /// Performs the host control-socket `Hello`/`HelloAck` handshake.
    ControlHandshake,
    /// Requests QEMU virtual-time control.
    RequestTimeControl,
    /// Receives setup file descriptors and node metadata from the host.
    ReceiveSetup,
    /// Maps and validates the shared-memory ABI region.
    MapSharedMemory,
    /// Arms the setup wake fd before acknowledging readiness.
    ArmWakeFd,
    /// Registers deterministic device, coverage, and white-box callbacks.
    RegisterCallbacks,
    /// Sends `SetupAck` only after setup has completed.
    SendSetupAck,
    /// Waits at the initial ceiling boot barrier.
    WaitBootBarrier,
    /// Represents the first architecturally visible guest instruction.
    FirstVisibleInstruction,
}

/// A planned plugin registration sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeControlRegistrationPlan {
    steps: Vec<PluginRegistrationStep>,
}

impl TimeControlRegistrationPlan {
    /// Returns the canonical registration plan required for time control.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            steps: CANONICAL_TIME_CONTROL_REGISTRATION_ORDER.to_vec(),
        }
    }

    /// Builds a registration plan from explicit steps.
    #[must_use]
    pub fn from_steps(steps: impl Into<Vec<PluginRegistrationStep>>) -> Self {
        Self {
            steps: steps.into(),
        }
    }

    /// Returns the registration steps in execution order.
    #[must_use]
    pub fn steps(&self) -> &[PluginRegistrationStep] {
        &self.steps
    }

    /// Validates the ordering constraints that make time control active before guest code.
    ///
    /// # Errors
    ///
    /// Returns [`TimeControlRegistrationError`] when a required step is absent
    /// or duplicated, or when time control, setup, callback registration, setup
    /// acknowledgement, or the boot barrier would run in an order that allows
    /// guest-visible time to advance before the plugin owns the virtual clock.
    pub fn validate(&self) -> Result<(), TimeControlRegistrationError> {
        self.validate_unique_steps()?;
        self.require_before(
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
        )?;
        self.require_before(
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
        )?;
        self.require_before(
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
        )?;
        self.require_before(
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
        )?;
        self.require_before(
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
        )?;
        self.require_before(
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::SendSetupAck,
        )?;
        self.require_before(
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
        )?;
        self.require_before(
            PluginRegistrationStep::RegisterCallbacks,
            PluginRegistrationStep::SendSetupAck,
        )?;
        self.require_before(
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::WaitBootBarrier,
        )?;
        self.require_before(
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        )?;
        self.require_before(
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::FirstVisibleInstruction,
        )?;
        Ok(())
    }

    fn validate_unique_steps(&self) -> Result<(), TimeControlRegistrationError> {
        let mut seen = BTreeSet::new();
        for step in &self.steps {
            if !seen.insert(*step) {
                return Err(TimeControlRegistrationError::DuplicateStep { step: *step });
            }
        }
        Ok(())
    }

    fn require_before(
        &self,
        earlier: PluginRegistrationStep,
        later: PluginRegistrationStep,
    ) -> Result<(), TimeControlRegistrationError> {
        let earlier_index = self
            .step_index(earlier)
            .ok_or(TimeControlRegistrationError::MissingStep { step: earlier })?;
        let later_index = self
            .step_index(later)
            .ok_or(TimeControlRegistrationError::MissingStep { step: later })?;

        if earlier_index < later_index {
            Ok(())
        } else {
            Err(TimeControlRegistrationError::OutOfOrderStep { earlier, later })
        }
    }

    fn step_index(&self, step: PluginRegistrationStep) -> Option<usize> {
        self.steps.iter().position(|candidate| *candidate == step)
    }
}

/// A time-control registration ordering error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TimeControlRegistrationError {
    /// A required registration step is absent.
    #[error("plugin registration step {step:?} is missing")]
    MissingStep {
        /// The missing step.
        step: PluginRegistrationStep,
    },
    /// A registration step appears more than once.
    #[error("plugin registration step {step:?} appears more than once")]
    DuplicateStep {
        /// The duplicated step.
        step: PluginRegistrationStep,
    },
    /// A registration step appears after a step that depends on it.
    #[error("plugin registration step {earlier:?} must run before {later:?}")]
    OutOfOrderStep {
        /// The step that must run first.
        earlier: PluginRegistrationStep,
        /// The step that depends on `earlier`.
        later: PluginRegistrationStep,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_control_registration_order_requests_control_before_first_instruction() {
        let plan = TimeControlRegistrationPlan::canonical();

        assert_eq!(plan.validate(), Ok(()));
        assert_order(
            &plan,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::FirstVisibleInstruction,
        );
        assert_order(
            &plan,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
        );
        assert_order(
            &plan,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
        );
    }

    #[test]
    fn time_control_registration_order_keeps_boot_barrier_before_guest_code() {
        let plan = TimeControlRegistrationPlan::canonical();

        assert_order(
            &plan,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::SendSetupAck,
        );
        assert_order(
            &plan,
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::WaitBootBarrier,
        );
        assert_order(
            &plan,
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        );
    }

    #[test]
    fn time_control_registration_order_rejects_late_or_missing_control() {
        let late_control = TimeControlRegistrationPlan::from_steps([
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        ]);
        let missing_control = TimeControlRegistrationPlan::from_steps([
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        ]);

        assert_eq!(
            late_control.validate(),
            Err(TimeControlRegistrationError::OutOfOrderStep {
                earlier: PluginRegistrationStep::RequestTimeControl,
                later: PluginRegistrationStep::ReceiveSetup,
            })
        );
        assert_eq!(
            missing_control.validate(),
            Err(TimeControlRegistrationError::MissingStep {
                step: PluginRegistrationStep::RequestTimeControl,
            })
        );
    }

    #[test]
    fn time_control_registration_order_rejects_setup_ack_before_wake_fd_arm() {
        let early_setup_ack = TimeControlRegistrationPlan::from_steps([
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        ]);

        assert_eq!(
            early_setup_ack.validate(),
            Err(TimeControlRegistrationError::OutOfOrderStep {
                earlier: PluginRegistrationStep::ArmWakeFd,
                later: PluginRegistrationStep::SendSetupAck,
            })
        );
    }

    #[test]
    fn time_control_registration_order_rejects_duplicate_steps() {
        let duplicate_control = TimeControlRegistrationPlan::from_steps([
            PluginRegistrationStep::ParseArguments,
            PluginRegistrationStep::ControlHandshake,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::RequestTimeControl,
            PluginRegistrationStep::ReceiveSetup,
            PluginRegistrationStep::MapSharedMemory,
            PluginRegistrationStep::ArmWakeFd,
            PluginRegistrationStep::RegisterCallbacks,
            PluginRegistrationStep::SendSetupAck,
            PluginRegistrationStep::WaitBootBarrier,
            PluginRegistrationStep::FirstVisibleInstruction,
        ]);

        assert_eq!(
            duplicate_control.validate(),
            Err(TimeControlRegistrationError::DuplicateStep {
                step: PluginRegistrationStep::RequestTimeControl,
            })
        );
    }

    fn assert_order(
        plan: &TimeControlRegistrationPlan,
        earlier: PluginRegistrationStep,
        later: PluginRegistrationStep,
    ) {
        let earlier_index = match plan.steps().iter().position(|step| *step == earlier) {
            Some(index) => index,
            None => panic!("missing earlier step {earlier:?}"),
        };
        let later_index = match plan.steps().iter().position(|step| *step == later) {
            Some(index) => index,
            None => panic!("missing later step {later:?}"),
        };
        assert!(earlier_index < later_index);
    }
}
