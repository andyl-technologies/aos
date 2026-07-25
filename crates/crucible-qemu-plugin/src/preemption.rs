//! Commanded preemption application through the patched QEMU capability.
//!
//! The scheduler's `Decision::Preemption` arrives at the plugin as a commanded
//! node-icount and either a vCPU switch or interrupt delivery. This module keeps
//! the plugin-side contract deterministic: validate the exact `[deadline,
//! ceiling]` authorization window, encode the command for QEMU's
//! `qemu_plugin_inject_preemption` export, and fail loudly instead of clamping
//! or deferring an out-of-window command.

use std::os::raw::{c_int, c_uint};

use thiserror::Error;

use crate::{
    RoundRobinConfig, RoundRobinError, RoundRobinRunState, RoundRobinTurn, SchedulerCeiling,
};

#[path = "preemption/injector.rs"]
mod injector;

/// Required QEMU plugin extension symbol for commanded preemption injection.
pub const QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL: &str = "qemu_plugin_inject_preemption";
/// Raw QEMU tag for a commanded vCPU switch.
pub const QEMU_PREEMPTION_KIND_VCPU_SWITCH: c_uint = 1;
/// Raw QEMU tag for a commanded interrupt delivery.
pub const QEMU_PREEMPTION_KIND_INTERRUPT_AT: c_uint = 2;
/// Unused raw argument value for command forms with fewer than three operands.
pub const QEMU_PREEMPTION_UNUSED_ARG: u32 = 0;

/// Plans an inter-vCPU interrupt on the fixed node-icount round-robin axis.
///
/// The sender observes the interrupt request at `send_icount`; the target sees it
/// no earlier than `send_icount + fixed_latency_icount`, rounded up to the next
/// `rr_switch_quantum` boundary. The resulting [`PluginPreemptionDecision`] uses
/// the same commanded-icount injection path as other scheduler preemptions.
///
/// # Errors
///
/// Returns [`PreemptionError`] when either vCPU id is outside `round_robin`,
/// when the sender and target are the same vCPU, or when the delivery icount
/// cannot be represented.
pub fn plan_deterministic_ipi_delivery(
    round_robin: RoundRobinConfig,
    send_icount: u64,
    sender_vcpu: u32,
    target_vcpu: u32,
    fixed_latency_icount: u64,
    irq: u32,
) -> Result<DeterministicIpiDelivery, PreemptionError> {
    validate_vcpu(sender_vcpu, round_robin.vcpu_count())?;
    validate_vcpu(target_vcpu, round_robin.vcpu_count())?;
    if sender_vcpu == target_vcpu {
        return Err(PreemptionError::SameVcpuIpi {
            vcpu_id: sender_vcpu,
        });
    }

    let earliest_delivery_icount = send_icount.checked_add(fixed_latency_icount).ok_or(
        PreemptionError::IpiDeliveryIcountOverflow {
            send_icount,
            fixed_latency_icount,
            rr_switch_quantum: round_robin.rr_switch_quantum(),
        },
    )?;
    let delivery_icount =
        next_round_robin_switch_boundary(earliest_delivery_icount, round_robin.rr_switch_quantum())
            .ok_or(PreemptionError::IpiDeliveryIcountOverflow {
                send_icount,
                fixed_latency_icount,
                rr_switch_quantum: round_robin.rr_switch_quantum(),
            })?;
    let decision = PluginPreemptionDecision::interrupt_at(delivery_icount, target_vcpu, irq);

    Ok(DeterministicIpiDelivery {
        send_icount,
        sender_vcpu,
        target_vcpu,
        fixed_latency_icount,
        earliest_delivery_icount,
        delivery_icount,
        rr_switch_quantum: round_robin.rr_switch_quantum(),
        irq,
        decision,
    })
}

/// QEMU's commanded preemption injection function.
///
/// The patched QEMU plugin API exports this symbol as a no-handle function. The
/// first argument is the aggregate node icount where the command must land, the
/// next two arguments carry the inclusive scheduler authorization window, the
/// kind argument is one of the `QEMU_PREEMPTION_KIND_*` tags, and the remaining
/// three arguments carry kind-specific vCPU/vector operands.
pub type QemuInjectPreemptionFn = extern "C" fn(u64, u64, u64, c_uint, u32, u32, u32) -> c_int;

/// Inclusive scheduler authorization window for a preemption command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreemptionWindow {
    deadline_icount: u64,
    ceiling_icount: u64,
}

/// Deterministic inter-vCPU interrupt delivery plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeterministicIpiDelivery {
    send_icount: u64,
    sender_vcpu: u32,
    target_vcpu: u32,
    fixed_latency_icount: u64,
    earliest_delivery_icount: u64,
    delivery_icount: u64,
    rr_switch_quantum: u64,
    irq: u32,
    decision: PluginPreemptionDecision,
}

impl DeterministicIpiDelivery {
    /// Returns the node icount at which the sender emitted the IPI.
    #[must_use]
    pub const fn send_icount(self) -> u64 {
        self.send_icount
    }

    /// Returns the vCPU that emitted the IPI.
    #[must_use]
    pub const fn sender_vcpu(self) -> u32 {
        self.sender_vcpu
    }

    /// Returns the vCPU that receives the IPI.
    #[must_use]
    pub const fn target_vcpu(self) -> u32 {
        self.target_vcpu
    }

    /// Returns the fixed modeled latency added to the sender icount.
    #[must_use]
    pub const fn fixed_latency_icount(self) -> u64 {
        self.fixed_latency_icount
    }

    /// Returns the earliest possible delivery icount before RR-boundary rounding.
    #[must_use]
    pub const fn earliest_delivery_icount(self) -> u64 {
        self.earliest_delivery_icount
    }

    /// Returns the RR-boundary icount at which the IPI is delivered.
    #[must_use]
    pub const fn delivery_icount(self) -> u64 {
        self.delivery_icount
    }

    /// Returns the fixed RR switch quantum used for delivery rounding.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }

    /// Returns the interrupt vector delivered to QEMU.
    #[must_use]
    pub const fn irq(self) -> u32 {
        self.irq
    }

    /// Returns the scheduler-commanded preemption decision for this delivery.
    #[must_use]
    pub const fn decision(self) -> PluginPreemptionDecision {
        self.decision
    }
}

impl PreemptionWindow {
    /// Builds an inclusive `[deadline, ceiling]` preemption authorization window.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError::InvalidWindow`] when `deadline_icount` is past
    /// the scheduler-published `ceiling`.
    pub const fn new(
        deadline_icount: u64,
        ceiling: SchedulerCeiling,
    ) -> Result<Self, PreemptionError> {
        if deadline_icount > ceiling.icount() {
            return Err(PreemptionError::InvalidWindow {
                deadline_icount,
                ceiling_icount: ceiling.icount(),
            });
        }
        Ok(Self {
            deadline_icount,
            ceiling_icount: ceiling.icount(),
        })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn deadline_icount(self) -> u64 {
        self.deadline_icount
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn ceiling_icount(self) -> u64 {
        self.ceiling_icount
    }

    /// Validates that `at_icount` is inside this authorization window.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError::CommandBeforeDeadline`] or
    /// [`PreemptionError::CommandBeyondCeiling`] when the command is outside the
    /// inclusive window.
    pub const fn validate_icount(self, at_icount: u64) -> Result<(), PreemptionError> {
        if at_icount < self.deadline_icount {
            return Err(PreemptionError::CommandBeforeDeadline {
                at_icount,
                deadline_icount: self.deadline_icount,
                ceiling_icount: self.ceiling_icount,
            });
        }
        if at_icount > self.ceiling_icount {
            return Err(PreemptionError::CommandBeyondCeiling {
                at_icount,
                deadline_icount: self.deadline_icount,
                ceiling_icount: self.ceiling_icount,
            });
        }
        Ok(())
    }
}

/// Plugin-local shape of `Decision::Preemption`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginPreemptionDecision {
    at_icount: u64,
    kind: PluginPreemptionKind,
}

impl PluginPreemptionDecision {
    /// Builds a commanded vCPU-switch decision.
    #[must_use]
    pub const fn vcpu_switch(at_icount: u64, from_vcpu: u32, to_vcpu: u32) -> Self {
        Self {
            at_icount,
            kind: PluginPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu },
        }
    }

    /// Builds a commanded interrupt-delivery decision.
    #[must_use]
    pub const fn interrupt_at(at_icount: u64, target_vcpu: u32, irq: u32) -> Self {
        Self {
            at_icount,
            kind: PluginPreemptionKind::InterruptAt { target_vcpu, irq },
        }
    }

    /// Returns the commanded aggregate node icount.
    #[must_use]
    pub const fn at_icount(self) -> u64 {
        self.at_icount
    }

    /// Returns the commanded preemption kind.
    #[must_use]
    pub const fn kind(self) -> PluginPreemptionKind {
        self.kind
    }

    /// Encodes this decision for the QEMU patch export after validation.
    ///
    /// # Errors
    ///
    /// Returns [`PreemptionError`] when the command icount is outside `window`,
    /// when a vCPU operand is outside `0..vcpu_count`, or when a vCPU-switch
    /// command names the same source and destination vCPU.
    pub fn to_qemu_command(
        self,
        window: PreemptionWindow,
        vcpu_count: u32,
    ) -> Result<QemuPreemptionCommand, PreemptionError> {
        window.validate_icount(self.at_icount)?;
        match self.kind {
            PluginPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                validate_vcpu(from_vcpu, vcpu_count)?;
                validate_vcpu(to_vcpu, vcpu_count)?;
                if from_vcpu == to_vcpu {
                    return Err(PreemptionError::NonSwitchingVcpuSwitch { vcpu_id: from_vcpu });
                }
                Ok(QemuPreemptionCommand {
                    at_icount: self.at_icount,
                    deadline_icount: window.deadline_icount(),
                    ceiling_icount: window.ceiling_icount(),
                    raw_kind: QEMU_PREEMPTION_KIND_VCPU_SWITCH,
                    arg0: from_vcpu,
                    arg1: to_vcpu,
                    arg2: QEMU_PREEMPTION_UNUSED_ARG,
                })
            }
            PluginPreemptionKind::InterruptAt { target_vcpu, irq } => {
                validate_vcpu(target_vcpu, vcpu_count)?;
                Ok(QemuPreemptionCommand {
                    at_icount: self.at_icount,
                    deadline_icount: window.deadline_icount(),
                    ceiling_icount: window.ceiling_icount(),
                    raw_kind: QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                    arg0: target_vcpu,
                    arg1: irq,
                    arg2: QEMU_PREEMPTION_UNUSED_ARG,
                })
            }
        }
    }
}

/// The kind of plugin-applied preemption command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginPreemptionKind {
    /// Force a vCPU switch at a commanded node icount.
    VcpuSwitch {
        /// The vCPU that must be current when the switch lands.
        from_vcpu: u32,
        /// The vCPU selected by the commanded switch.
        to_vcpu: u32,
    },
    /// Deliver an interrupt at a commanded node icount.
    InterruptAt {
        /// The vCPU receiving the interrupt.
        target_vcpu: u32,
        /// The interrupt vector delivered by QEMU.
        irq: u32,
    },
}

/// Raw command passed to QEMU's preemption-injection export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuPreemptionCommand {
    at_icount: u64,
    deadline_icount: u64,
    ceiling_icount: u64,
    raw_kind: c_uint,
    arg0: u32,
    arg1: u32,
    arg2: u32,
}

impl QemuPreemptionCommand {
    /// Returns the commanded aggregate node icount.
    #[must_use]
    pub const fn at_icount(self) -> u64 {
        self.at_icount
    }

    /// Returns the inclusive scheduler deadline sent to QEMU.
    #[must_use]
    pub const fn deadline_icount(self) -> u64 {
        self.deadline_icount
    }

    /// Returns the inclusive scheduler ceiling sent to QEMU.
    #[must_use]
    pub const fn ceiling_icount(self) -> u64 {
        self.ceiling_icount
    }

    /// Returns the raw QEMU preemption kind tag.
    #[must_use]
    pub const fn raw_kind(self) -> c_uint {
        self.raw_kind
    }

    /// Returns the first raw QEMU operand.
    #[must_use]
    pub const fn arg0(self) -> u32 {
        self.arg0
    }

    /// Returns the second raw QEMU operand.
    #[must_use]
    pub const fn arg1(self) -> u32 {
        self.arg1
    }

    /// Returns the third raw QEMU operand.
    #[must_use]
    pub const fn arg2(self) -> u32 {
        self.arg2
    }
}

/// Required plugin-side handle for commanded preemption injection.
#[derive(Clone, Copy, Debug)]
pub struct PluginPreemptionInjector {
    inject_preemption: QemuInjectPreemptionFn,
}

/// Evidence that one preemption command was accepted by QEMU and local state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginPreemptionApplication {
    decision: PluginPreemptionDecision,
    command: QemuPreemptionCommand,
    round_robin_turn: Option<RoundRobinTurn>,
}

impl PluginPreemptionApplication {
    /// Returns the scheduler decision that was applied.
    #[must_use]
    pub const fn decision(self) -> PluginPreemptionDecision {
        self.decision
    }

    /// Returns the raw command sent to QEMU.
    #[must_use]
    pub const fn command(self) -> QemuPreemptionCommand {
        self.command
    }

    /// Returns the local round-robin state transition, if this was a vCPU switch.
    #[must_use]
    pub const fn round_robin_turn(self) -> Option<RoundRobinTurn> {
        self.round_robin_turn
    }
}

/// Error returned by commanded preemption validation or injection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PreemptionError {
    /// The required QEMU plugin symbol is unavailable.
    #[error("required preemption-injection capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// The missing QEMU plugin symbol.
        symbol: &'static str,
    },
    /// The scheduler supplied a malformed authorization window.
    #[error("preemption window deadline {deadline_icount} is past ceiling {ceiling_icount}")]
    InvalidWindow {
        /// Inclusive lower bound that should have preceded the ceiling.
        deadline_icount: u64,
        /// Inclusive upper bound from the scheduler ceiling.
        ceiling_icount: u64,
    },
    /// The command would land before the authorized deadline.
    #[error(
        "preemption at {at_icount} is before authorized window [{deadline_icount}, {ceiling_icount}]"
    )]
    CommandBeforeDeadline {
        /// Rejected command icount.
        at_icount: u64,
        /// Inclusive lower bound.
        deadline_icount: u64,
        /// Inclusive upper bound.
        ceiling_icount: u64,
    },
    /// The command would land beyond the scheduler ceiling.
    #[error(
        "preemption at {at_icount} is beyond authorized window [{deadline_icount}, {ceiling_icount}]"
    )]
    CommandBeyondCeiling {
        /// Rejected command icount.
        at_icount: u64,
        /// Inclusive lower bound.
        deadline_icount: u64,
        /// Inclusive upper bound.
        ceiling_icount: u64,
    },
    /// A command referenced a vCPU outside the configured range.
    #[error("preemption referenced vCPU {vcpu_id} outside configured vCPU count {vcpu_count}")]
    VcpuOutOfRange {
        /// Rejected vCPU id.
        vcpu_id: u32,
        /// Configured vCPU count.
        vcpu_count: u32,
    },
    /// A vCPU-switch command did not change vCPUs.
    #[error("preemption vCPU switch must change vCPUs, got vCPU {vcpu_id}")]
    NonSwitchingVcpuSwitch {
        /// Rejected source and destination vCPU.
        vcpu_id: u32,
    },
    /// An inter-vCPU IPI targeted the sender.
    #[error("inter-vCPU IPI must target a different vCPU, got vCPU {vcpu_id}")]
    SameVcpuIpi {
        /// Rejected sender and target vCPU.
        vcpu_id: u32,
    },
    /// The modeled deterministic IPI delivery icount overflowed.
    #[error(
        "IPI delivery icount overflowed for send {send_icount}, latency {fixed_latency_icount}, quantum {rr_switch_quantum}"
    )]
    IpiDeliveryIcountOverflow {
        /// Sender-observed node icount.
        send_icount: u64,
        /// Fixed modeled IPI latency.
        fixed_latency_icount: u64,
        /// Fixed RR switch quantum used for boundary rounding.
        rr_switch_quantum: u64,
    },
    /// QEMU rejected the preemption command.
    #[error("QEMU rejected preemption at {at_icount} with kind {raw_kind} and status {status}")]
    CapabilityRejected {
        /// Commanded node icount rejected by QEMU.
        at_icount: u64,
        /// Raw preemption kind tag rejected by QEMU.
        raw_kind: c_uint,
        /// QEMU error status.
        status: c_int,
    },
    /// The local round-robin cursor rejected the commanded switch.
    #[error("round-robin rejected commanded preemption: {0}")]
    RoundRobin(#[from] RoundRobinError),
}

fn validate_vcpu(vcpu_id: u32, vcpu_count: u32) -> Result<(), PreemptionError> {
    if vcpu_id >= vcpu_count {
        return Err(PreemptionError::VcpuOutOfRange {
            vcpu_id,
            vcpu_count,
        });
    }
    Ok(())
}

fn next_round_robin_switch_boundary(earliest_icount: u64, rr_switch_quantum: u64) -> Option<u64> {
    let remainder = earliest_icount % rr_switch_quantum;
    if remainder == 0 {
        Some(earliest_icount)
    } else {
        earliest_icount.checked_add(rr_switch_quantum - remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard};

    static TEST_PREEMPTION_CALLS: Mutex<Vec<QemuPreemptionCommand>> = Mutex::new(Vec::new());
    static TEST_PREEMPTION_SERIAL: Mutex<()> = Mutex::new(());

    fn preemption_test_guard() -> MutexGuard<'static, ()> {
        match TEST_PREEMPTION_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn reset_calls() {
        match TEST_PREEMPTION_CALLS.lock() {
            Ok(mut calls) => calls.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }

    fn recorded_calls() -> Vec<QemuPreemptionCommand> {
        match TEST_PREEMPTION_CALLS.lock() {
            Ok(calls) => calls.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    extern "C" fn accept_preemption(
        at_icount: u64,
        deadline_icount: u64,
        ceiling_icount: u64,
        raw_kind: c_uint,
        arg0: u32,
        arg1: u32,
        arg2: u32,
    ) -> c_int {
        match TEST_PREEMPTION_CALLS.lock() {
            Ok(mut calls) => calls.push(QemuPreemptionCommand {
                at_icount,
                deadline_icount,
                ceiling_icount,
                raw_kind,
                arg0,
                arg1,
                arg2,
            }),
            Err(poisoned) => poisoned.into_inner().push(QemuPreemptionCommand {
                at_icount,
                deadline_icount,
                ceiling_icount,
                raw_kind,
                arg0,
                arg1,
                arg2,
            }),
        }
        0
    }

    extern "C" fn reject_preemption(
        at_icount: u64,
        deadline_icount: u64,
        ceiling_icount: u64,
        raw_kind: c_uint,
        arg0: u32,
        arg1: u32,
        arg2: u32,
    ) -> c_int {
        match TEST_PREEMPTION_CALLS.lock() {
            Ok(mut calls) => calls.push(QemuPreemptionCommand {
                at_icount,
                deadline_icount,
                ceiling_icount,
                raw_kind,
                arg0,
                arg1,
                arg2,
            }),
            Err(poisoned) => poisoned.into_inner().push(QemuPreemptionCommand {
                at_icount,
                deadline_icount,
                ceiling_icount,
                raw_kind,
                arg0,
                arg1,
                arg2,
            }),
        }
        -7
    }

    fn run_state() -> RoundRobinRunState {
        let config = RoundRobinConfig::new(3, 16)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"));
        RoundRobinRunState::new(config, 0)
            .unwrap_or_else(|error| panic!("initial vCPU should validate: {error}"))
    }

    fn four_vcpu_round_robin() -> RoundRobinConfig {
        RoundRobinConfig::new(4, 16)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"))
    }

    #[test]
    fn deterministic_ipi_delivery_uses_fixed_latency_and_next_rr_switch() {
        let delivery = plan_deterministic_ipi_delivery(four_vcpu_round_robin(), 18, 0, 2, 5, 0xf0)
            .unwrap_or_else(|error| panic!("IPI delivery should plan: {error}"));

        assert_eq!(delivery.send_icount(), 18);
        assert_eq!(delivery.sender_vcpu(), 0);
        assert_eq!(delivery.target_vcpu(), 2);
        assert_eq!(delivery.fixed_latency_icount(), 5);
        assert_eq!(delivery.earliest_delivery_icount(), 23);
        assert_eq!(delivery.delivery_icount(), 32);
        assert_eq!(delivery.rr_switch_quantum(), 16);
        assert_eq!(delivery.irq(), 0xf0);
        assert_eq!(
            delivery.decision(),
            PluginPreemptionDecision::interrupt_at(32, 2, 0xf0)
        );

        let boundary_delivery =
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), 24, 1, 3, 8, 0xf1)
                .unwrap_or_else(|error| panic!("IPI boundary delivery should plan: {error}"));
        assert_eq!(boundary_delivery.earliest_delivery_icount(), 32);
        assert_eq!(boundary_delivery.delivery_icount(), 32);
        assert_eq!(
            boundary_delivery.decision(),
            PluginPreemptionDecision::interrupt_at(32, 3, 0xf1)
        );
    }

    #[test]
    fn deterministic_ipi_delivery_rejects_bad_vcpu_pairs_and_overflow() {
        assert_eq!(
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), 18, 4, 2, 5, 0xf0),
            Err(PreemptionError::VcpuOutOfRange {
                vcpu_id: 4,
                vcpu_count: 4,
            })
        );
        assert_eq!(
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), 18, 0, 4, 5, 0xf0),
            Err(PreemptionError::VcpuOutOfRange {
                vcpu_id: 4,
                vcpu_count: 4,
            })
        );
        assert_eq!(
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), 18, 1, 1, 5, 0xf0),
            Err(PreemptionError::SameVcpuIpi { vcpu_id: 1 })
        );
        assert_eq!(
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), u64::MAX, 0, 1, 1, 0xf0),
            Err(PreemptionError::IpiDeliveryIcountOverflow {
                send_icount: u64::MAX,
                fixed_latency_icount: 1,
                rr_switch_quantum: 16,
            })
        );
        assert_eq!(
            plan_deterministic_ipi_delivery(four_vcpu_round_robin(), u64::MAX - 1, 0, 1, 0, 0xf0),
            Err(PreemptionError::IpiDeliveryIcountOverflow {
                send_icount: u64::MAX - 1,
                fixed_latency_icount: 0,
                rr_switch_quantum: 16,
            })
        );
    }

    #[test]
    fn preemption_injector_requires_qemu_capability_and_valid_window() {
        assert_eq!(
            PluginPreemptionInjector::require(None).map(|_injector| ()),
            Err(PreemptionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
            })
        );
        assert_eq!(
            PreemptionWindow::new(11, SchedulerCeiling::new(10)),
            Err(PreemptionError::InvalidWindow {
                deadline_icount: 11,
                ceiling_icount: 10,
            })
        );
        assert!(PluginPreemptionInjector::require(Some(accept_preemption)).is_ok());
    }

    #[test]
    fn preemption_injector_dispatches_vcpu_switch_at_commanded_icount() {
        let _guard = preemption_test_guard();
        reset_calls();
        let injector = PluginPreemptionInjector::require(Some(accept_preemption))
            .unwrap_or_else(|error| panic!("preemption injector should validate: {error}"));
        let mut state = run_state();
        assert_eq!(
            state.retire(0, 5),
            Ok(RoundRobinTurn::Continue {
                vcpu_id: 0,
                remaining_in_quantum: 11,
            })
        );
        let window = PreemptionWindow::new(100, SchedulerCeiling::new(200))
            .unwrap_or_else(|error| panic!("preemption window should validate: {error}"));

        let application = injector
            .apply_decision(
                PluginPreemptionDecision::vcpu_switch(120, 0, 2),
                window,
                &mut state,
            )
            .unwrap_or_else(|error| panic!("preemption should apply: {error}"));

        assert_eq!(
            application.command(),
            QemuPreemptionCommand {
                at_icount: 120,
                deadline_icount: 100,
                ceiling_icount: 200,
                raw_kind: QEMU_PREEMPTION_KIND_VCPU_SWITCH,
                arg0: 0,
                arg1: 2,
                arg2: QEMU_PREEMPTION_UNUSED_ARG,
            }
        );
        assert_eq!(
            application.round_robin_turn(),
            Some(RoundRobinTurn::Switch {
                from_vcpu: 0,
                to_vcpu: 2,
                rr_switch_quantum: 16,
            })
        );
        assert_eq!(state.current_vcpu(), 2);
        assert_eq!(state.remaining_in_quantum(), 16);
        assert_eq!(recorded_calls(), vec![application.command()]);
    }

    #[test]
    fn preemption_injector_dispatches_interrupt_without_round_robin_switch() {
        let _guard = preemption_test_guard();
        reset_calls();
        let injector = PluginPreemptionInjector::require(Some(accept_preemption))
            .unwrap_or_else(|error| panic!("preemption injector should validate: {error}"));
        let mut state = run_state();
        let window = PreemptionWindow::new(100, SchedulerCeiling::new(200))
            .unwrap_or_else(|error| panic!("preemption window should validate: {error}"));

        let application = injector
            .apply_decision(
                PluginPreemptionDecision::interrupt_at(140, 1, 32),
                window,
                &mut state,
            )
            .unwrap_or_else(|error| panic!("interrupt preemption should apply: {error}"));

        assert_eq!(
            application.command(),
            QemuPreemptionCommand {
                at_icount: 140,
                deadline_icount: 100,
                ceiling_icount: 200,
                raw_kind: QEMU_PREEMPTION_KIND_INTERRUPT_AT,
                arg0: 1,
                arg1: 32,
                arg2: QEMU_PREEMPTION_UNUSED_ARG,
            }
        );
        assert_eq!(application.round_robin_turn(), None);
        assert_eq!(state.current_vcpu(), 0);
        assert_eq!(state.remaining_in_quantum(), 16);
        assert_eq!(recorded_calls(), vec![application.command()]);
    }

    #[test]
    fn preemption_injector_rejects_out_of_window_without_clamping_or_calling_qemu() {
        let _guard = preemption_test_guard();
        reset_calls();
        let injector = PluginPreemptionInjector::require(Some(accept_preemption))
            .unwrap_or_else(|error| panic!("preemption injector should validate: {error}"));
        let mut state = run_state();
        let window = PreemptionWindow::new(100, SchedulerCeiling::new(200))
            .unwrap_or_else(|error| panic!("preemption window should validate: {error}"));

        assert_eq!(
            injector.apply_decision(
                PluginPreemptionDecision::vcpu_switch(99, 0, 1),
                window,
                &mut state,
            ),
            Err(PreemptionError::CommandBeforeDeadline {
                at_icount: 99,
                deadline_icount: 100,
                ceiling_icount: 200,
            })
        );
        assert_eq!(
            injector.apply_decision(
                PluginPreemptionDecision::interrupt_at(201, 1, 32),
                window,
                &mut state,
            ),
            Err(PreemptionError::CommandBeyondCeiling {
                at_icount: 201,
                deadline_icount: 100,
                ceiling_icount: 200,
            })
        );
        assert_eq!(recorded_calls(), Vec::new());
        assert_eq!(state.current_vcpu(), 0);
        assert_eq!(state.remaining_in_quantum(), 16);
    }

    #[test]
    fn preemption_injector_localizes_malformed_or_rejected_commands() {
        let _guard = preemption_test_guard();
        reset_calls();
        let injector = PluginPreemptionInjector::require(Some(reject_preemption))
            .unwrap_or_else(|error| panic!("preemption injector should validate: {error}"));
        let mut state = run_state();
        let window = PreemptionWindow::new(100, SchedulerCeiling::new(200))
            .unwrap_or_else(|error| panic!("preemption window should validate: {error}"));

        assert_eq!(
            PluginPreemptionDecision::vcpu_switch(120, 0, 3)
                .to_qemu_command(window, state.vcpu_count()),
            Err(PreemptionError::VcpuOutOfRange {
                vcpu_id: 3,
                vcpu_count: 3,
            })
        );
        assert_eq!(
            PluginPreemptionDecision::vcpu_switch(120, 0, 0)
                .to_qemu_command(window, state.vcpu_count()),
            Err(PreemptionError::NonSwitchingVcpuSwitch { vcpu_id: 0 })
        );
        assert_eq!(
            injector.apply_decision(
                PluginPreemptionDecision::vcpu_switch(120, 1, 2),
                window,
                &mut state,
            ),
            Err(PreemptionError::RoundRobin(
                RoundRobinError::WrongCurrentVcpu {
                    expected_vcpu: 0,
                    observed_vcpu: 1,
                }
            ))
        );
        assert_eq!(recorded_calls(), Vec::new());

        assert_eq!(
            injector.apply_decision(
                PluginPreemptionDecision::vcpu_switch(120, 0, 2),
                window,
                &mut state,
            ),
            Err(PreemptionError::CapabilityRejected {
                at_icount: 120,
                raw_kind: QEMU_PREEMPTION_KIND_VCPU_SWITCH,
                status: -7,
            })
        );
        assert_eq!(
            recorded_calls(),
            vec![QemuPreemptionCommand {
                at_icount: 120,
                deadline_icount: 100,
                ceiling_icount: 200,
                raw_kind: QEMU_PREEMPTION_KIND_VCPU_SWITCH,
                arg0: 0,
                arg1: 2,
                arg2: QEMU_PREEMPTION_UNUSED_ARG,
            }]
        );
        assert_eq!(state.current_vcpu(), 0);
        assert_eq!(state.remaining_in_quantum(), 16);
    }
}
