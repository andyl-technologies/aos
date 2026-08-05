//! Plugin time-control registration order.
//!
//! The QEMU plugin ABI executes this safe contract while holding raw QEMU handles.

use std::collections::BTreeSet;
use std::os::raw::{c_int, c_void};

use thiserror::Error;

mod request;
pub use request::{PluginTimeControlRequestError, QemuRequestTimeControlFn};

/// QEMU plugin API symbol used to acquire virtual-time control.
pub const QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL: &str = "qemu_plugin_request_time_control";
/// Crucible-stable plugin API symbol used to enqueue idle time advances.
pub const QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL: &str = "qemu_plugin_advance_time_ns";
/// Crucible-stable plugin API symbol used to register queued-advance completion.
pub const QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL: &str =
    "qemu_plugin_register_time_advance_cb";
/// QEMU plugin API predicate used by the no-warp patch.
pub const QEMU_PLUGIN_HAS_TIME_CONTROL_SYMBOL: &str = "qemu_plugin_has_time_control";
/// Upstream QEMU plugin API symbol used by the time-control owner.
pub const QEMU_PLUGIN_UPDATE_NS_SYMBOL: &str = "qemu_plugin_update_ns";
/// Largest `-icount shift=N` value representable by a `u64` nanosecond scale.
pub const MAX_PLUGIN_ICOUNT_SHIFT: u8 = 63;

/// QEMU's callback-safe queued virtual-time advance function.
///
/// Zero means the request was queued. A negative errno-style value rejects the
/// request before ownership transfers to QEMU.
pub type QemuAdvanceTimeNsFn = extern "C" fn(i64) -> c_int;

/// Normal-main-loop completion callback for a queued virtual-time advance.
pub type QemuTimeAdvanceCompletionCbFn = extern "C" fn(c_int, i64, *mut c_void);

/// QEMU function that registers the queued-advance completion callback.
///
/// Zero means the callback was installed. A negative errno-style value rejects
/// registration, including while another advance remains outstanding.
pub type QemuRegisterTimeAdvanceCbFn =
    extern "C" fn(Option<QemuTimeAdvanceCompletionCbFn>, *mut c_void) -> c_int;

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

/// Proof that this plugin instance acquired QEMU virtual-time control.
#[derive(Debug)]
pub struct PluginTimeControlOwnership {
    _private: (),
}

impl PluginTimeControlOwnership {
    /// Records time-control ownership after the fixed registration path completes.
    ///
    /// [`crate::PluginRegistrationReady`] is non-forgeable and can be produced
    /// only after the fixed registration sequencer has recorded
    /// [`PluginRegistrationStep::RequestTimeControl`], which corresponds to a
    /// successful [`QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL`] call in the FFI
    /// entry point.
    #[must_use]
    pub const fn acquired_after_registration(_ready: crate::PluginRegistrationReady) -> Self {
        Self { _private: () }
    }
}

/// A scheduler-published execution ceiling in aggregate node-icount units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerCeiling {
    icount: u64,
}

impl SchedulerCeiling {
    /// Builds a scheduler ceiling.
    #[must_use]
    pub const fn new(icount: u64) -> Self {
        Self { icount }
    }

    /// Returns the ceiling icount.
    #[must_use]
    pub const fn icount(self) -> u64 {
        self.icount
    }
}

/// Explicit scheduler authorization for an idle virtual-time jump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerAuthorizedIdleJump {
    from_icount: u64,
    target_icount: u64,
    ceiling_icount: u64,
    _private: (),
}

impl SchedulerAuthorizedIdleJump {
    /// Returns the icount at which the authorization was issued.
    #[must_use]
    pub const fn from_icount(self) -> u64 {
        self.from_icount
    }

    /// Returns the scheduler-authorized jump target.
    #[must_use]
    pub const fn target_icount(self) -> u64 {
        self.target_icount
    }

    /// Returns the ceiling that bounded the authorization.
    #[must_use]
    pub const fn ceiling_icount(self) -> u64 {
        self.ceiling_icount
    }

    /// Projects the authorized target into virtual nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError`] when the target cannot be represented with
    /// the fixed icount shift.
    pub fn target_virtual_ns(self, icount_shift: u8) -> Result<u64, PluginClockError> {
        project_virtual_ns(self.target_icount, icount_shift)
    }
}

/// The only accepted sources of virtual-clock movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginClockAdvanceSource {
    /// Guest instructions retired under the scheduler ceiling.
    GuestInstructions,
    /// An explicit scheduler-authorized idle jump.
    SchedulerAuthorizedIdleJump,
}

/// A completed plugin virtual-clock advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginClockAdvance {
    source: PluginClockAdvanceSource,
    from_icount: u64,
    to_icount: u64,
    virtual_ns: u64,
}

impl PluginClockAdvance {
    /// Returns the source that authorized this advance.
    #[must_use]
    pub const fn source(self) -> PluginClockAdvanceSource {
        self.source
    }

    /// Returns the icount before the advance.
    #[must_use]
    pub const fn from_icount(self) -> u64 {
        self.from_icount
    }

    /// Returns the icount after the advance.
    #[must_use]
    pub const fn to_icount(self) -> u64 {
        self.to_icount
    }

    /// Returns the virtual nanoseconds after the advance.
    #[must_use]
    pub const fn virtual_ns(self) -> u64 {
        self.virtual_ns
    }
}

/// Required handle for enqueueing idle jumps through QEMU.
#[derive(Clone, Copy, Debug)]
pub struct QueuedIdleAdvance {
    advance_time_ns: QemuAdvanceTimeNsFn,
}

impl QueuedIdleAdvance {
    /// Requires QEMU's callback-safe queued-advance export.
    ///
    /// # Errors
    ///
    /// Returns [`QueuedIdleAdvanceError::CapabilityUnavailable`] when the
    /// `qemu_plugin_advance_time_ns` export was not resolved.
    pub fn require(
        advance_time_ns: Option<QemuAdvanceTimeNsFn>,
    ) -> Result<Self, QueuedIdleAdvanceError> {
        let Some(advance_time_ns) = advance_time_ns else {
            return Err(QueuedIdleAdvanceError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL,
            });
        };

        Ok(Self { advance_time_ns })
    }

    /// Enqueues a QEMU virtual-time advance without claiming completion.
    ///
    /// # Errors
    ///
    /// Returns [`QueuedIdleAdvanceError::VirtualTimeOutOfRange`] when the target
    /// cannot be passed through QEMU's signed nanosecond ABI, or
    /// [`QueuedIdleAdvanceError::EnqueueRejected`] when QEMU rejects the request.
    pub fn enqueue(
        &self,
        target_virtual_ns: u64,
    ) -> Result<PendingIdleAdvance, QueuedIdleAdvanceError> {
        let qemu_target_ns = i64::try_from(target_virtual_ns).map_err(|_error| {
            QueuedIdleAdvanceError::VirtualTimeOutOfRange { target_virtual_ns }
        })?;
        let status = (self.advance_time_ns)(qemu_target_ns);
        if status != 0 {
            return Err(QueuedIdleAdvanceError::EnqueueRejected {
                target_virtual_ns,
                status,
            });
        }
        Ok(PendingIdleAdvance {
            target_virtual_ns,
            completion_pending: true,
        })
    }
}

/// Evidence that QEMU accepted an advance whose completion is still pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingIdleAdvance {
    target_virtual_ns: u64,
    completion_pending: bool,
}

/// Completion delivered by QEMU's normal-main-loop advance callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAdvanceCompletion {
    status: c_int,
    target_virtual_ns: i64,
}

impl TimeAdvanceCompletion {
    /// Captures the exact status and target delivered by QEMU.
    #[must_use]
    pub const fn from_qemu(status: c_int, target_virtual_ns: i64) -> Self {
        Self {
            status,
            target_virtual_ns,
        }
    }

    /// Returns QEMU's errno-style completion status.
    #[must_use]
    pub const fn status(self) -> c_int {
        self.status
    }

    /// Returns the signed target echoed by QEMU.
    #[must_use]
    pub const fn target_virtual_ns(self) -> i64 {
        self.target_virtual_ns
    }
}

impl PendingIdleAdvance {
    /// Returns the absolute QEMU virtual nanosecond target that was queued.
    #[must_use]
    pub const fn target_virtual_ns(self) -> u64 {
        self.target_virtual_ns
    }

    /// Returns whether normal-main-loop completion is still required.
    #[must_use]
    pub const fn completion_pending(self) -> bool {
        self.completion_pending
    }

    /// Validates the later normal-main-loop completion for this request.
    ///
    /// # Errors
    ///
    /// Returns [`QueuedIdleAdvanceError::CompletionFailed`] when QEMU reports a
    /// failure, or [`QueuedIdleAdvanceError::CompletionTargetMismatch`] when the
    /// callback does not echo this request's exact target.
    pub fn validate_completion(
        mut self,
        completion: TimeAdvanceCompletion,
    ) -> Result<Self, QueuedIdleAdvanceError> {
        if completion.status != 0 {
            return Err(QueuedIdleAdvanceError::CompletionFailed {
                target_virtual_ns: self.target_virtual_ns,
                status: completion.status,
            });
        }
        let Ok(completed_target) = u64::try_from(completion.target_virtual_ns) else {
            return Err(QueuedIdleAdvanceError::CompletionTargetMismatch {
                expected_target_virtual_ns: self.target_virtual_ns,
                completed_target_virtual_ns: completion.target_virtual_ns,
            });
        };
        if completed_target != self.target_virtual_ns {
            return Err(QueuedIdleAdvanceError::CompletionTargetMismatch {
                expected_target_virtual_ns: self.target_virtual_ns,
                completed_target_virtual_ns: completion.target_virtual_ns,
            });
        }
        self.completion_pending = false;
        Ok(self)
    }
}

/// Plugin-owned virtual clock state.
///
/// This type deliberately has no wall-clock or monotonic-clock input. It can
/// move only by guest retirement bounded by [`SchedulerCeiling`] or by consuming
/// a [`SchedulerAuthorizedIdleJump`] issued for the current icount.
#[derive(Debug)]
pub struct PluginVirtualClock {
    current_icount: u64,
    icount_shift: u8,
    _ownership: PluginTimeControlOwnership,
}

impl PluginVirtualClock {
    /// Creates plugin virtual-clock state after time control has been acquired.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError::IcountShiftTooLarge`] when `icount_shift`
    /// cannot be represented as a `u64` nanosecond scale, or
    /// [`PluginClockError::VirtualTimeOverflow`] when `initial_icount` cannot be
    /// projected with that shift.
    pub fn new(
        initial_icount: u64,
        icount_shift: u8,
        ownership: PluginTimeControlOwnership,
    ) -> Result<Self, PluginClockError> {
        project_virtual_ns(initial_icount, icount_shift)?;
        Ok(Self {
            current_icount: initial_icount,
            icount_shift,
            _ownership: ownership,
        })
    }

    /// Returns the aggregate node icount currently owned by the plugin.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the fixed `-icount shift=N` scale.
    #[must_use]
    pub const fn icount_shift(&self) -> u8 {
        self.icount_shift
    }

    /// Returns the current virtual nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError::VirtualTimeOverflow`] when the current icount
    /// cannot be projected with this clock's fixed shift.
    pub fn current_virtual_ns(&self) -> Result<u64, PluginClockError> {
        project_virtual_ns(self.current_icount, self.icount_shift)
    }

    /// Advances by retired guest instructions bounded by a scheduler ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError`] when the icount addition overflows, when the
    /// resulting icount would exceed `ceiling`, or when the virtual nanosecond
    /// projection overflows.
    pub fn advance_guest_instructions(
        &mut self,
        retired_instructions: u64,
        ceiling: SchedulerCeiling,
    ) -> Result<PluginClockAdvance, PluginClockError> {
        let target_icount = self
            .current_icount
            .checked_add(retired_instructions)
            .ok_or(PluginClockError::IcountOverflow {
                current_icount: self.current_icount,
                delta_icount: retired_instructions,
            })?;
        self.advance_to_icount(
            PluginClockAdvanceSource::GuestInstructions,
            target_icount,
            ceiling,
        )
    }

    /// Authorizes an idle jump against the current icount and scheduler ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError`] when `target_icount` moves backward, exceeds
    /// `ceiling`, or cannot be projected to virtual nanoseconds with the fixed
    /// icount shift.
    pub fn authorize_idle_jump(
        &self,
        target_icount: u64,
        ceiling: SchedulerCeiling,
    ) -> Result<SchedulerAuthorizedIdleJump, PluginClockError> {
        validate_target(
            self.current_icount,
            target_icount,
            ceiling,
            self.icount_shift,
        )?;
        Ok(SchedulerAuthorizedIdleJump {
            from_icount: self.current_icount,
            target_icount,
            ceiling_icount: ceiling.icount(),
            _private: (),
        })
    }

    /// Advances by consuming an explicit scheduler-authorized idle jump.
    ///
    /// # Errors
    ///
    /// Returns [`PluginClockError::StaleIdleJumpAuthorization`] when the
    /// authorization was issued for a different current icount, or another
    /// [`PluginClockError`] if the target no longer validates.
    pub fn advance_authorized_idle_jump(
        &mut self,
        authorization: SchedulerAuthorizedIdleJump,
    ) -> Result<PluginClockAdvance, PluginClockError> {
        if authorization.from_icount != self.current_icount {
            return Err(PluginClockError::StaleIdleJumpAuthorization {
                authorized_from_icount: authorization.from_icount,
                current_icount: self.current_icount,
            });
        }
        self.advance_to_icount(
            PluginClockAdvanceSource::SchedulerAuthorizedIdleJump,
            authorization.target_icount,
            SchedulerCeiling::new(authorization.ceiling_icount),
        )
    }

    fn advance_to_icount(
        &mut self,
        source: PluginClockAdvanceSource,
        target_icount: u64,
        ceiling: SchedulerCeiling,
    ) -> Result<PluginClockAdvance, PluginClockError> {
        validate_target(
            self.current_icount,
            target_icount,
            ceiling,
            self.icount_shift,
        )?;
        let from_icount = self.current_icount;
        let virtual_ns = project_virtual_ns(target_icount, self.icount_shift)?;
        self.current_icount = target_icount;
        Ok(PluginClockAdvance {
            source,
            from_icount,
            to_icount: target_icount,
            virtual_ns,
        })
    }
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

/// An error produced while advancing the plugin-owned virtual clock.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginClockError {
    /// The configured fixed icount shift cannot be represented.
    #[error("plugin icount shift {shift} exceeds maximum {max}")]
    IcountShiftTooLarge {
        /// Rejected shift.
        shift: u8,
        /// Maximum supported shift.
        max: u8,
    },
    /// Adding retired instructions to the current icount overflowed.
    #[error("plugin icount overflow at current icount {current_icount} plus delta {delta_icount}")]
    IcountOverflow {
        /// Current aggregate node icount.
        current_icount: u64,
        /// Requested icount delta.
        delta_icount: u64,
    },
    /// A requested advance would move the virtual clock backward.
    #[error("plugin virtual clock cannot move backward from {current_icount} to {target_icount}")]
    BackwardsAdvance {
        /// Current aggregate node icount.
        current_icount: u64,
        /// Rejected target icount.
        target_icount: u64,
    },
    /// A requested advance exceeds the scheduler-published ceiling.
    #[error(
        "plugin virtual clock target {target_icount} exceeds scheduler ceiling {ceiling_icount}"
    )]
    BeyondSchedulerCeiling {
        /// Rejected target icount.
        target_icount: u64,
        /// Scheduler-published ceiling.
        ceiling_icount: u64,
    },
    /// The icount-to-nanosecond projection overflowed.
    #[error("plugin virtual time overflows at icount {icount} with icount shift {icount_shift}")]
    VirtualTimeOverflow {
        /// Aggregate node icount being projected.
        icount: u64,
        /// Fixed icount shift.
        icount_shift: u8,
    },
    /// An idle-jump authorization no longer matches the current clock.
    #[error(
        "idle jump authorization was issued at icount {authorized_from_icount}, current icount is {current_icount}"
    )]
    StaleIdleJumpAuthorization {
        /// Icount captured when the jump was authorized.
        authorized_from_icount: u64,
        /// Current aggregate node icount.
        current_icount: u64,
    },
}

/// An error produced while requiring or enqueueing QEMU's idle advance.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QueuedIdleAdvanceError {
    /// QEMU does not expose the required queued-advance symbol.
    #[error("required QEMU plugin queued idle-advance symbol {symbol} is unavailable")]
    CapabilityUnavailable {
        /// Missing QEMU plugin symbol.
        symbol: &'static str,
    },
    /// The target virtual time cannot pass through QEMU's signed nanosecond ABI.
    #[error("queued idle advance target {target_virtual_ns}ns exceeds QEMU int64 range")]
    VirtualTimeOutOfRange {
        /// Rejected absolute virtual-time target.
        target_virtual_ns: u64,
    },
    /// QEMU rejected the request before accepting ownership.
    #[error("QEMU rejected queued idle advance to {target_virtual_ns}ns with status {status}")]
    EnqueueRejected {
        /// Rejected absolute virtual-time target.
        target_virtual_ns: u64,
        /// Negative errno-style status returned by QEMU.
        status: c_int,
    },
    /// The accepted request later failed in QEMU's queued worker.
    #[error("QEMU failed queued idle advance to {target_virtual_ns}ns with status {status}")]
    CompletionFailed {
        /// Requested absolute virtual-time target.
        target_virtual_ns: u64,
        /// Negative errno-style completion status.
        status: c_int,
    },
    /// QEMU's completion did not identify the outstanding request.
    #[error(
        "QEMU completed idle advance target {completed_target_virtual_ns}ns while {expected_target_virtual_ns}ns was pending"
    )]
    CompletionTargetMismatch {
        /// Outstanding request target.
        expected_target_virtual_ns: u64,
        /// Target supplied by the completion callback.
        completed_target_virtual_ns: i64,
    },
}

fn validate_target(
    current_icount: u64,
    target_icount: u64,
    ceiling: SchedulerCeiling,
    icount_shift: u8,
) -> Result<(), PluginClockError> {
    if target_icount < current_icount {
        return Err(PluginClockError::BackwardsAdvance {
            current_icount,
            target_icount,
        });
    }
    if target_icount > ceiling.icount() {
        return Err(PluginClockError::BeyondSchedulerCeiling {
            target_icount,
            ceiling_icount: ceiling.icount(),
        });
    }
    project_virtual_ns(target_icount, icount_shift)?;
    Ok(())
}

fn project_virtual_ns(icount: u64, icount_shift: u8) -> Result<u64, PluginClockError> {
    let scale =
        1u64.checked_shl(u32::from(icount_shift))
            .ok_or(PluginClockError::IcountShiftTooLarge {
                shift: icount_shift,
                max: MAX_PLUGIN_ICOUNT_SHIFT,
            })?;
    icount
        .checked_mul(scale)
        .ok_or(PluginClockError::VirtualTimeOverflow {
            icount,
            icount_shift,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use crucible_shmem::{KIND_VM, NodeSlot, authorize_advance_ceiling};

    thread_local! {
        static LAST_DIRECT_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
    }

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

    #[test]
    fn time_control_clock_advances_by_guest_instructions_up_to_ceiling() {
        let mut clock = owned_clock(10, 2);

        let advance = match clock.advance_guest_instructions(5, SchedulerCeiling::new(15)) {
            Ok(advance) => advance,
            Err(error) => panic!("guest retirement within ceiling should advance: {error}"),
        };

        assert_eq!(
            advance.source(),
            PluginClockAdvanceSource::GuestInstructions
        );
        assert_eq!(advance.from_icount(), 10);
        assert_eq!(advance.to_icount(), 15);
        assert_eq!(advance.virtual_ns(), 60);
        assert_eq!(clock.current_icount(), 15);
        assert_eq!(clock.current_virtual_ns(), Ok(60));
    }

    #[test]
    fn time_control_clock_rejects_guest_instruction_advance_past_ceiling() {
        let mut clock = owned_clock(10, 0);

        assert_eq!(
            clock.advance_guest_instructions(6, SchedulerCeiling::new(15)),
            Err(PluginClockError::BeyondSchedulerCeiling {
                target_icount: 16,
                ceiling_icount: 15,
            })
        );
        assert_eq!(clock.current_icount(), 10);
    }

    #[test]
    fn time_control_clock_advances_by_scheduler_authorized_idle_jump() {
        let mut clock = owned_clock(20, 1);
        let authorization = match clock.authorize_idle_jump(32, SchedulerCeiling::new(40)) {
            Ok(authorization) => authorization,
            Err(error) => panic!("idle jump inside ceiling should authorize: {error}"),
        };

        assert_eq!(authorization.from_icount(), 20);
        assert_eq!(authorization.target_icount(), 32);
        assert_eq!(authorization.ceiling_icount(), 40);

        let advance = match clock.advance_authorized_idle_jump(authorization) {
            Ok(advance) => advance,
            Err(error) => panic!("authorized idle jump should advance: {error}"),
        };

        assert_eq!(
            advance.source(),
            PluginClockAdvanceSource::SchedulerAuthorizedIdleJump
        );
        assert_eq!(advance.from_icount(), 20);
        assert_eq!(advance.to_icount(), 32);
        assert_eq!(advance.virtual_ns(), 64);
        assert_eq!(clock.current_icount(), 32);
    }

    #[test]
    fn queued_idle_advance_requires_qemu_enqueue_symbol() {
        let Err(error) = QueuedIdleAdvance::require(None) else {
            panic!("missing queued advance symbol should fail closed");
        };

        assert_eq!(
            error,
            QueuedIdleAdvanceError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL,
            }
        );
    }

    #[test]
    fn queued_idle_advance_reports_pending_completion() {
        set_last_direct_advance_ns(-1);
        let advance = match QueuedIdleAdvance::require(Some(test_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("queued advance symbol should be accepted: {error}"),
        };

        let pending = match advance.enqueue(4096) {
            Ok(pending) => pending,
            Err(error) => panic!("queued advance should accept signed target: {error}"),
        };

        assert_eq!(last_direct_advance_ns(), 4096);
        assert_eq!(pending.target_virtual_ns(), 4096);
        assert!(pending.completion_pending());
        let completed = pending
            .validate_completion(TimeAdvanceCompletion::from_qemu(0, 4096))
            .unwrap_or_else(|error| panic!("matching completion should validate: {error}"));
        assert!(!completed.completion_pending());
    }

    #[test]
    fn queued_idle_advance_rejects_failed_or_mismatched_completion() {
        let pending = PendingIdleAdvance {
            target_virtual_ns: 4096,
            completion_pending: true,
        };
        assert_eq!(
            pending.validate_completion(TimeAdvanceCompletion::from_qemu(-34, 4096)),
            Err(QueuedIdleAdvanceError::CompletionFailed {
                target_virtual_ns: 4096,
                status: -34,
            })
        );
        assert_eq!(
            pending.validate_completion(TimeAdvanceCompletion::from_qemu(0, 4097)),
            Err(QueuedIdleAdvanceError::CompletionTargetMismatch {
                expected_target_virtual_ns: 4096,
                completed_target_virtual_ns: 4097,
            })
        );
    }

    #[test]
    fn queued_idle_advance_preserves_qemu_rejection_status() {
        let advance = match QueuedIdleAdvance::require(Some(test_rejected_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("queued advance symbol should be accepted: {error}"),
        };

        assert_eq!(
            advance.enqueue(4096),
            Err(QueuedIdleAdvanceError::EnqueueRejected {
                target_virtual_ns: 4096,
                status: -16,
            })
        );
    }

    #[test]
    fn queued_idle_advance_rejects_targets_outside_qemu_signed_range() {
        set_last_direct_advance_ns(-1);
        let advance = match QueuedIdleAdvance::require(Some(test_direct_advance)) {
            Ok(advance) => advance,
            Err(error) => panic!("queued advance symbol should be accepted: {error}"),
        };

        assert_eq!(
            advance.enqueue(i64::MAX as u64 + 1),
            Err(QueuedIdleAdvanceError::VirtualTimeOutOfRange {
                target_virtual_ns: i64::MAX as u64 + 1,
            })
        );
        assert_eq!(last_direct_advance_ns(), -1);
    }

    #[test]
    fn time_control_clock_rejects_stale_idle_jump_authorization() {
        let mut clock = owned_clock(20, 0);
        let authorization = match clock.authorize_idle_jump(25, SchedulerCeiling::new(30)) {
            Ok(authorization) => authorization,
            Err(error) => panic!("idle jump should authorize: {error}"),
        };
        if let Err(error) = clock.advance_guest_instructions(1, SchedulerCeiling::new(30)) {
            panic!("guest instruction should advance before stale jump check: {error}");
        }

        assert_eq!(
            clock.advance_authorized_idle_jump(authorization),
            Err(PluginClockError::StaleIdleJumpAuthorization {
                authorized_from_icount: 20,
                current_icount: 21,
            })
        );
    }

    #[test]
    fn time_control_clock_rejects_backward_jump_and_virtual_overflow() {
        let clock = owned_clock(20, 0);

        assert_eq!(
            clock.authorize_idle_jump(19, SchedulerCeiling::new(30)),
            Err(PluginClockError::BackwardsAdvance {
                current_icount: 20,
                target_icount: 19,
            })
        );
        assert!(matches!(
            PluginVirtualClock::new(1, MAX_PLUGIN_ICOUNT_SHIFT + 1, ownership()),
            Err(PluginClockError::IcountShiftTooLarge { .. })
        ));
        assert_eq!(
            PluginVirtualClock::new(2, MAX_PLUGIN_ICOUNT_SHIFT, ownership()).err(),
            Some(PluginClockError::VirtualTimeOverflow {
                icount: 2,
                icount_shift: MAX_PLUGIN_ICOUNT_SHIFT,
            })
        );
    }

    fn owned_clock(initial_icount: u64, icount_shift: u8) -> PluginVirtualClock {
        match PluginVirtualClock::new(initial_icount, icount_shift, ownership()) {
            Ok(clock) => clock,
            Err(error) => panic!("test clock should construct: {error}"),
        }
    }

    fn ownership() -> PluginTimeControlOwnership {
        PluginTimeControlOwnership::acquired_after_registration(registration_ready())
    }

    fn registration_ready() -> crate::PluginRegistrationReady {
        let mut sequence = crate::PluginRegistrationSequence::new();
        let args = crate::PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap_or_else(|error| panic!("test args should parse: {error}"));
        let mut setup_ack = None;
        for step in CANONICAL_TIME_CONTROL_REGISTRATION_ORDER {
            let result = if step == PluginRegistrationStep::RegisterCallbacks {
                sequence
                    .register_callbacks_for_test(
                        &args,
                        Some(time_control_test_deadline),
                        Some(time_control_test_direct_advance),
                        crate::CoverageCapabilities::none(),
                    )
                    .map(|_capabilities| ())
            } else if step == PluginRegistrationStep::SendSetupAck {
                sequence.record_test_ready_setup_ack().map(|ack| {
                    setup_ack = Some(ack);
                })
            } else if step == PluginRegistrationStep::WaitBootBarrier {
                let ack = setup_ack
                    .take()
                    .unwrap_or_else(|| panic!("setup ack should precede boot barrier"));
                let slot = NodeSlot::new(KIND_VM);
                publish_boot_barrier_ceiling(&slot);
                sequence.wait_boot_barrier(ack, &slot, 0).map(|_release| ())
            } else {
                sequence.record_step(step)
            };
            if let Err(error) = result {
                panic!("canonical registration step {step:?} should record: {error}");
            }
        }
        match sequence.finish() {
            Ok(ready) => ready,
            Err(error) => panic!("canonical registration should finish: {error}"),
        }
    }

    extern "C" fn time_control_test_deadline() -> i64 {
        1
    }

    extern "C" fn time_control_test_direct_advance(_target_virtual_ns: i64) -> c_int {
        0
    }

    fn publish_boot_barrier_ceiling(slot: &NodeSlot) {
        let ceiling = authorize_advance_ceiling(0, crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT, None)
            .unwrap_or_else(|error| panic!("boot barrier ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("boot barrier ceiling should publish: {error}"));
    }

    extern "C" fn test_direct_advance(target_virtual_ns: i64) -> c_int {
        set_last_direct_advance_ns(target_virtual_ns);
        0
    }

    extern "C" fn test_rejected_direct_advance(_target_virtual_ns: i64) -> c_int {
        -16
    }

    fn set_last_direct_advance_ns(value: i64) {
        LAST_DIRECT_ADVANCE_NS.with(|cell| cell.set(value));
    }

    fn last_direct_advance_ns() -> i64 {
        LAST_DIRECT_ADVANCE_NS.with(|cell| cell.get())
    }
}
