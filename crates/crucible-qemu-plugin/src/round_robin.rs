//! Deterministic round-robin vCPU scheduling state.
//!
//! QEMU's single-threaded TCG accelerator serializes vCPU callbacks. This module
//! models the plugin state that remains inside that serialized thread: fixed
//! `rr_switch_quantum` accounting, ascending vCPU rotation, per-vCPU halt state,
//! and the all-vCPUs-halted predicate that feeds the idle hot-loop.

use thiserror::Error;

use crate::{
    ExactDeadlineError, IdleHotLoopError, IdleWakePlan, PerVcpuDeadlineReport, SchedulerCeiling,
    aggregate_multi_vcpu_deadline, compute_idle_wake_plan,
};

/// Validated deterministic round-robin configuration for one QEMU node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundRobinConfig {
    vcpu_count: u32,
    rr_switch_quantum: u64,
}

impl RoundRobinConfig {
    /// Validates the vCPU count and fixed node-icount switch quantum.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::ZeroVcpuCount`] when `vcpu_count` is zero, or
    /// [`RoundRobinError::ZeroSwitchQuantum`] when `rr_switch_quantum` is zero.
    pub const fn new(vcpu_count: u32, rr_switch_quantum: u64) -> Result<Self, RoundRobinError> {
        if vcpu_count == 0 {
            return Err(RoundRobinError::ZeroVcpuCount);
        }
        if rr_switch_quantum == 0 {
            return Err(RoundRobinError::ZeroSwitchQuantum);
        }
        Ok(Self {
            vcpu_count,
            rr_switch_quantum,
        })
    }

    /// Returns the configured vCPU count.
    #[must_use]
    pub const fn vcpu_count(self) -> u32 {
        self.vcpu_count
    }

    /// Returns the fixed node-icount quantum for each vCPU turn.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }

    /// Returns the next vCPU in fixed ascending rotation.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `vcpu_id` is not in
    /// `0..self.vcpu_count()`.
    pub const fn next_vcpu(self, vcpu_id: u32) -> Result<u32, RoundRobinError> {
        if vcpu_id >= self.vcpu_count {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id,
                vcpu_count: self.vcpu_count,
            });
        }
        Ok(if vcpu_id + 1 == self.vcpu_count {
            0
        } else {
            vcpu_id + 1
        })
    }
}

/// The result of accounting or yielding one vCPU turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundRobinTurn {
    /// The same vCPU continues running until the current quantum is exhausted.
    Continue {
        /// vCPU that remains current.
        vcpu_id: u32,
        /// Node-icount ticks left in the current vCPU turn.
        remaining_in_quantum: u64,
    },
    /// The cursor advanced to another vCPU in fixed ascending order.
    Switch {
        /// vCPU whose turn just completed or yielded after halting.
        from_vcpu: u32,
        /// Next vCPU selected by ascending round-robin rotation.
        to_vcpu: u32,
        /// Fixed quantum granted to the selected vCPU turn.
        rr_switch_quantum: u64,
    },
}

/// Deterministic round-robin cursor for the active RUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundRobinRunState {
    config: RoundRobinConfig,
    current_vcpu: u32,
    remaining_in_quantum: u64,
}

impl RoundRobinRunState {
    /// Starts a RUN at `initial_vcpu`.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `initial_vcpu` is not in
    /// `0..config.vcpu_count()`.
    pub const fn new(config: RoundRobinConfig, initial_vcpu: u32) -> Result<Self, RoundRobinError> {
        if initial_vcpu >= config.vcpu_count {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id: initial_vcpu,
                vcpu_count: config.vcpu_count,
            });
        }
        Ok(Self {
            config,
            current_vcpu: initial_vcpu,
            remaining_in_quantum: config.rr_switch_quantum,
        })
    }

    /// Returns the current vCPU.
    #[must_use]
    pub const fn current_vcpu(self) -> u32 {
        self.current_vcpu
    }

    /// Returns the configured vCPU count for this RUN cursor.
    #[must_use]
    pub const fn vcpu_count(self) -> u32 {
        self.config.vcpu_count()
    }

    /// Returns the fixed node-icount quantum for this RUN cursor.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.config.rr_switch_quantum()
    }

    /// Returns the node-icount ticks left before the next switch.
    #[must_use]
    pub const fn remaining_in_quantum(self) -> u64 {
        self.remaining_in_quantum
    }

    /// Returns the retired node-icount position inside the current quantum.
    #[must_use]
    pub const fn cursor_position(self) -> u64 {
        self.config.rr_switch_quantum - self.remaining_in_quantum
    }

    /// Accounts retired node-icount ticks for the current vCPU.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::WrongCurrentVcpu`] when QEMU reports progress
    /// for a vCPU other than [`Self::current_vcpu`], or
    /// [`RoundRobinError::QuantumOverrun`] when `retired_node_icount` exceeds the
    /// remaining fixed quantum.
    pub fn retire(
        &mut self,
        vcpu_id: u32,
        retired_node_icount: u64,
    ) -> Result<RoundRobinTurn, RoundRobinError> {
        if vcpu_id != self.current_vcpu {
            return Err(RoundRobinError::WrongCurrentVcpu {
                expected_vcpu: self.current_vcpu,
                observed_vcpu: vcpu_id,
            });
        }
        if retired_node_icount > self.remaining_in_quantum {
            return Err(RoundRobinError::QuantumOverrun {
                vcpu_id,
                retired_node_icount,
                remaining_in_quantum: self.remaining_in_quantum,
            });
        }

        self.remaining_in_quantum -= retired_node_icount;
        if self.remaining_in_quantum == 0 {
            let from_vcpu = self.current_vcpu;
            let to_vcpu = self.config.next_vcpu(from_vcpu)?;
            self.current_vcpu = to_vcpu;
            self.remaining_in_quantum = self.config.rr_switch_quantum;
            Ok(RoundRobinTurn::Switch {
                from_vcpu,
                to_vcpu,
                rr_switch_quantum: self.config.rr_switch_quantum,
            })
        } else {
            Ok(RoundRobinTurn::Continue {
                vcpu_id,
                remaining_in_quantum: self.remaining_in_quantum,
            })
        }
    }

    /// Validates a scheduler-commanded vCPU switch against the current cursor.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::WrongCurrentVcpu`] when `from_vcpu` is not the
    /// current cursor, [`RoundRobinError::VcpuOutOfRange`] when `to_vcpu` is
    /// outside `0..self.vcpu_count()`, or
    /// [`RoundRobinError::DegenerateVcpuSwitch`] when the command would keep the
    /// same vCPU running.
    pub const fn validate_commanded_switch(
        self,
        from_vcpu: u32,
        to_vcpu: u32,
    ) -> Result<(), RoundRobinError> {
        if from_vcpu != self.current_vcpu {
            return Err(RoundRobinError::WrongCurrentVcpu {
                expected_vcpu: self.current_vcpu,
                observed_vcpu: from_vcpu,
            });
        }
        if to_vcpu >= self.config.vcpu_count {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id: to_vcpu,
                vcpu_count: self.config.vcpu_count,
            });
        }
        if from_vcpu == to_vcpu {
            return Err(RoundRobinError::DegenerateVcpuSwitch { vcpu_id: from_vcpu });
        }
        Ok(())
    }

    /// Applies a scheduler-commanded vCPU switch and starts a fresh fixed quantum.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::validate_commanded_switch`].
    pub fn force_commanded_switch(
        &mut self,
        from_vcpu: u32,
        to_vcpu: u32,
    ) -> Result<RoundRobinTurn, RoundRobinError> {
        self.validate_commanded_switch(from_vcpu, to_vcpu)?;
        self.current_vcpu = to_vcpu;
        self.remaining_in_quantum = self.config.rr_switch_quantum;
        Ok(RoundRobinTurn::Switch {
            from_vcpu,
            to_vcpu,
            rr_switch_quantum: self.config.rr_switch_quantum,
        })
    }

    /// Advances past a halted current vCPU to the next runnable vCPU.
    ///
    /// Returns [`None`] when every vCPU is halted and the node should enter the
    /// all-halted idle path. Returns [`RoundRobinTurn::Continue`] without
    /// changing the cursor when the current vCPU is still runnable.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuCountMismatch`] when `tracker` was created
    /// for a different vCPU count than the round-robin configuration. Returns
    /// [`RoundRobinError::VcpuOutOfRange`] if the stored cursor is outside the
    /// tracker range.
    pub fn advance_past_halted_current(
        &mut self,
        tracker: &VcpuHaltTracker,
    ) -> Result<Option<RoundRobinTurn>, RoundRobinError> {
        self.validate_tracker(tracker)?;

        if !tracker.is_halted(self.current_vcpu)? {
            return Ok(Some(RoundRobinTurn::Continue {
                vcpu_id: self.current_vcpu,
                remaining_in_quantum: self.remaining_in_quantum,
            }));
        }

        let from_vcpu = self.current_vcpu;
        let Some(to_vcpu) = tracker.next_running_after(from_vcpu)? else {
            return Ok(None);
        };

        self.current_vcpu = to_vcpu;
        self.remaining_in_quantum = self.config.rr_switch_quantum;
        Ok(Some(RoundRobinTurn::Switch {
            from_vcpu,
            to_vcpu,
            rr_switch_quantum: self.config.rr_switch_quantum,
        }))
    }

    fn validate_tracker(&self, tracker: &VcpuHaltTracker) -> Result<(), RoundRobinError> {
        let tracker_vcpu_count = tracker.vcpu_count();
        if tracker_vcpu_count != self.config.vcpu_count {
            return Err(RoundRobinError::VcpuCountMismatch {
                config_vcpu_count: self.config.vcpu_count,
                tracker_vcpu_count,
            });
        }
        Ok(())
    }
}

/// Per-vCPU halt state for the node-idle predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcpuHaltTracker {
    halted: Vec<bool>,
    halted_count: u32,
}

impl VcpuHaltTracker {
    /// Creates a halt tracker for all vCPUs in one node.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::ZeroVcpuCount`] when `vcpu_count` is zero.
    pub fn new(vcpu_count: u32) -> Result<Self, RoundRobinError> {
        if vcpu_count == 0 {
            return Err(RoundRobinError::ZeroVcpuCount);
        }
        Ok(Self {
            halted: vec![false; vcpu_count as usize],
            halted_count: 0,
        })
    }

    /// Returns the configured vCPU count.
    #[must_use]
    pub fn vcpu_count(&self) -> u32 {
        self.halted.len() as u32
    }

    /// Returns the number of currently halted vCPUs.
    #[must_use]
    pub const fn halted_count(&self) -> u32 {
        self.halted_count
    }

    /// Returns whether `vcpu_id` is halted.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `vcpu_id` is outside the
    /// configured range.
    pub fn is_halted(&self, vcpu_id: u32) -> Result<bool, RoundRobinError> {
        self.halted
            .get(vcpu_id as usize)
            .copied()
            .ok_or_else(|| RoundRobinError::VcpuOutOfRange {
                vcpu_id,
                vcpu_count: self.vcpu_count(),
            })
    }

    /// Marks one vCPU halted after QEMU reports an idle callback.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `vcpu_id` is outside the
    /// configured range.
    pub fn mark_halted(&mut self, vcpu_id: u32) -> Result<(), RoundRobinError> {
        let vcpu_count = self.vcpu_count();
        let Some(halted) = self.halted.get_mut(vcpu_id as usize) else {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id,
                vcpu_count,
            });
        };
        if !*halted {
            *halted = true;
            self.halted_count += 1;
        }
        Ok(())
    }

    /// Marks one vCPU running after resume, interrupt, IPI, or commanded preemption.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `vcpu_id` is outside the
    /// configured range.
    pub fn mark_running(&mut self, vcpu_id: u32) -> Result<(), RoundRobinError> {
        let vcpu_count = self.vcpu_count();
        let Some(halted) = self.halted.get_mut(vcpu_id as usize) else {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id,
                vcpu_count,
            });
        };
        if *halted {
            *halted = false;
            self.halted_count -= 1;
        }
        Ok(())
    }

    /// Returns the next runnable vCPU after `vcpu_id` in fixed ascending order.
    ///
    /// The scan wraps at the configured vCPU count. It returns [`None`] when
    /// every vCPU is halted.
    ///
    /// # Errors
    ///
    /// Returns [`RoundRobinError::VcpuOutOfRange`] when `vcpu_id` is outside the
    /// configured range.
    pub fn next_running_after(&self, vcpu_id: u32) -> Result<Option<u32>, RoundRobinError> {
        let vcpu_count = self.vcpu_count();
        if vcpu_id >= vcpu_count {
            return Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id,
                vcpu_count,
            });
        }

        let mut candidate = vcpu_id;
        for _ in 0..vcpu_count {
            candidate = if candidate + 1 == vcpu_count {
                0
            } else {
                candidate + 1
            };
            if !self.halted[candidate as usize] {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Returns whether the node is idle because every vCPU is halted.
    #[must_use]
    pub fn all_halted(&self) -> bool {
        self.halted_count as usize == self.halted.len()
    }
}

/// Computes a node-idle wake plan only when every vCPU is halted.
///
/// # Errors
///
/// Returns [`RoundRobinError`] when a per-vCPU deadline set is malformed, the
/// deadline cannot be converted to icount units, or the scheduler ceiling is
/// behind the current node icount.
// crucible-lint: allow rust-allow -- forwards the full idle wake input set (tracker, per-vCPU deadlines, inbound, ceiling, device-hold, device deadline) to `compute_idle_wake_plan`; bundling would only shuffle the same fields.
#[allow(clippy::too_many_arguments)]
pub fn compute_all_halted_idle_wake_plan(
    tracker: &VcpuHaltTracker,
    current_icount: u64,
    icount_shift: u8,
    per_vcpu_deadlines: &[PerVcpuDeadlineReport],
    next_inbound_delivery_icount: Option<u64>,
    ceiling: SchedulerCeiling,
    device_io_holding_ticks: bool,
    device_completion_deadline_icount: Option<u64>,
) -> Result<Option<IdleWakePlan>, RoundRobinError> {
    if !tracker.all_halted() {
        return Ok(None);
    }

    let exact_deadline =
        aggregate_multi_vcpu_deadline(u64::from(tracker.vcpu_count()), per_vcpu_deadlines)
            .map_err(RoundRobinError::DeadlineAggregation)?;
    compute_idle_wake_plan(
        current_icount,
        icount_shift,
        exact_deadline,
        next_inbound_delivery_icount,
        ceiling,
        device_io_holding_ticks,
        device_completion_deadline_icount,
    )
    .map(Some)
    .map_err(RoundRobinError::IdleWake)
}

/// Error returned by round-robin and per-vCPU idle tracking.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RoundRobinError {
    /// A round-robin or halt tracker was created with no vCPUs.
    #[error("round-robin vCPU count must be non-zero")]
    ZeroVcpuCount,
    /// The fixed switch quantum was zero.
    #[error("round-robin switch quantum must be non-zero")]
    ZeroSwitchQuantum,
    /// A vCPU id was outside the configured range.
    #[error("vCPU {vcpu_id} is outside configured vCPU count {vcpu_count}")]
    VcpuOutOfRange {
        /// Rejected vCPU id.
        vcpu_id: u32,
        /// Configured vCPU count.
        vcpu_count: u32,
    },
    /// A halt tracker was created for a different vCPU count than the cursor.
    #[error(
        "round-robin configured for {config_vcpu_count} vCPUs, halt tracker covers {tracker_vcpu_count}"
    )]
    VcpuCountMismatch {
        /// vCPU count from the round-robin configuration.
        config_vcpu_count: u32,
        /// vCPU count covered by the halt tracker.
        tracker_vcpu_count: u32,
    },
    /// A commanded switch would keep the same vCPU running.
    #[error("round-robin commanded switch must change vCPUs, got vCPU {vcpu_id}")]
    DegenerateVcpuSwitch {
        /// Rejected source and destination vCPU.
        vcpu_id: u32,
    },
    /// QEMU reported progress for a vCPU other than the current cursor.
    #[error("round-robin expected vCPU {expected_vcpu}, observed vCPU {observed_vcpu}")]
    WrongCurrentVcpu {
        /// Expected current vCPU.
        expected_vcpu: u32,
        /// Observed vCPU.
        observed_vcpu: u32,
    },
    /// A vCPU retired more ticks than the current fixed quantum permits.
    #[error(
        "vCPU {vcpu_id} retired {retired_node_icount} ticks with only {remaining_in_quantum} left"
    )]
    QuantumOverrun {
        /// Current vCPU.
        vcpu_id: u32,
        /// Retired node-icount ticks reported for this callback.
        retired_node_icount: u64,
        /// Node-icount ticks left in the fixed quantum.
        remaining_in_quantum: u64,
    },
    /// Per-vCPU deadline aggregation failed.
    #[error("multi-vCPU deadline aggregation failed: {0}")]
    DeadlineAggregation(ExactDeadlineError),
    /// Idle wake planning failed after all vCPUs halted.
    #[error("all-halted idle wake planning failed: {0}")]
    IdleWake(IdleHotLoopError),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{ExactDeadlineReport, IdleWakeCause};

    #[test]
    fn round_robin_run_uses_fixed_quantum_and_ascending_rotation() {
        let config = RoundRobinConfig::new(4, 4096)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"));
        let mut state = RoundRobinRunState::new(config, 0)
            .unwrap_or_else(|error| panic!("initial vCPU should validate: {error}"));

        assert_eq!(
            state.retire(0, 2048),
            Ok(RoundRobinTurn::Continue {
                vcpu_id: 0,
                remaining_in_quantum: 2048,
            })
        );
        assert_eq!(
            state.retire(0, 2048),
            Ok(RoundRobinTurn::Switch {
                from_vcpu: 0,
                to_vcpu: 1,
                rr_switch_quantum: 4096,
            })
        );
        assert_eq!(state.current_vcpu(), 1);
        assert_eq!(state.remaining_in_quantum(), 4096);

        for (from, to) in [(1, 2), (2, 3), (3, 0), (0, 1)] {
            assert_eq!(
                state.retire(from, 4096),
                Ok(RoundRobinTurn::Switch {
                    from_vcpu: from,
                    to_vcpu: to,
                    rr_switch_quantum: 4096,
                })
            );
        }
    }

    #[test]
    fn round_robin_rejects_wrong_vcpu_and_quantum_overrun() {
        let config = RoundRobinConfig::new(2, 8)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"));
        let mut state = RoundRobinRunState::new(config, 0)
            .unwrap_or_else(|error| panic!("initial vCPU should validate: {error}"));

        assert_eq!(
            RoundRobinConfig::new(0, 8),
            Err(RoundRobinError::ZeroVcpuCount)
        );
        assert_eq!(
            RoundRobinConfig::new(2, 0),
            Err(RoundRobinError::ZeroSwitchQuantum)
        );
        assert_eq!(
            RoundRobinRunState::new(config, 2),
            Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id: 2,
                vcpu_count: 2,
            })
        );
        assert_eq!(
            state.retire(1, 1),
            Err(RoundRobinError::WrongCurrentVcpu {
                expected_vcpu: 0,
                observed_vcpu: 1,
            })
        );
        assert_eq!(
            state.retire(0, 9),
            Err(RoundRobinError::QuantumOverrun {
                vcpu_id: 0,
                retired_node_icount: 9,
                remaining_in_quantum: 8,
            })
        );
    }

    #[test]
    fn halted_current_vcpu_yields_to_next_running_vcpu_without_node_idle() {
        let config = RoundRobinConfig::new(3, 8)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"));
        let mut state = RoundRobinRunState::new(config, 0)
            .unwrap_or_else(|error| panic!("initial vCPU should validate: {error}"));
        let mut tracker = VcpuHaltTracker::new(3)
            .unwrap_or_else(|error| panic!("halt tracker should validate: {error}"));

        assert_eq!(
            state.retire(0, 3),
            Ok(RoundRobinTurn::Continue {
                vcpu_id: 0,
                remaining_in_quantum: 5,
            })
        );
        tracker
            .mark_halted(0)
            .unwrap_or_else(|error| panic!("vCPU 0 should halt: {error}"));
        tracker
            .mark_halted(1)
            .unwrap_or_else(|error| panic!("vCPU 1 should halt: {error}"));
        assert!(!tracker.all_halted());
        assert_eq!(tracker.next_running_after(0), Ok(Some(2)));

        assert_eq!(
            state.advance_past_halted_current(&tracker),
            Ok(Some(RoundRobinTurn::Switch {
                from_vcpu: 0,
                to_vcpu: 2,
                rr_switch_quantum: 8,
            }))
        );
        assert_eq!(state.current_vcpu(), 2);
        assert_eq!(state.remaining_in_quantum(), 8);

        let short_tracker = VcpuHaltTracker::new(2)
            .unwrap_or_else(|error| panic!("short halt tracker should validate: {error}"));
        assert_eq!(
            state.advance_past_halted_current(&short_tracker),
            Err(RoundRobinError::VcpuCountMismatch {
                config_vcpu_count: 3,
                tracker_vcpu_count: 2,
            })
        );
    }

    #[test]
    fn vcpu_halt_tracker_requires_every_vcpu_before_node_idle() {
        let mut tracker = VcpuHaltTracker::new(3)
            .unwrap_or_else(|error| panic!("halt tracker should validate: {error}"));

        assert!(!tracker.all_halted());
        tracker
            .mark_halted(0)
            .unwrap_or_else(|error| panic!("vCPU 0 should halt: {error}"));
        tracker
            .mark_halted(2)
            .unwrap_or_else(|error| panic!("vCPU 2 should halt: {error}"));
        assert_eq!(tracker.halted_count(), 2);
        assert!(!tracker.all_halted());

        tracker
            .mark_halted(1)
            .unwrap_or_else(|error| panic!("vCPU 1 should halt: {error}"));
        tracker
            .mark_halted(1)
            .unwrap_or_else(|error| panic!("duplicate halt should be idempotent: {error}"));
        assert_eq!(tracker.halted_count(), 3);
        assert!(tracker.all_halted());

        tracker
            .mark_running(2)
            .unwrap_or_else(|error| panic!("resume should clear halt: {error}"));
        assert!(!tracker.all_halted());
        assert_eq!(tracker.halted_count(), 2);
        assert_eq!(
            tracker.mark_halted(3),
            Err(RoundRobinError::VcpuOutOfRange {
                vcpu_id: 3,
                vcpu_count: 3,
            })
        );
    }

    #[test]
    fn all_halted_idle_wake_uses_minimum_per_vcpu_deadline() {
        let mut tracker = VcpuHaltTracker::new(3)
            .unwrap_or_else(|error| panic!("halt tracker should validate: {error}"));
        tracker
            .mark_halted(0)
            .unwrap_or_else(|error| panic!("vCPU 0 should halt: {error}"));
        tracker
            .mark_halted(1)
            .unwrap_or_else(|error| panic!("vCPU 1 should halt: {error}"));
        let reports = [
            PerVcpuDeadlineReport::new(0, ExactDeadlineReport::Armed { deadline_ns: 120 }),
            PerVcpuDeadlineReport::new(1, ExactDeadlineReport::NoArmedTimer),
            PerVcpuDeadlineReport::new(2, ExactDeadlineReport::Armed { deadline_ns: 80 }),
        ];

        assert_eq!(
            compute_all_halted_idle_wake_plan(
                &tracker,
                10,
                0,
                &reports,
                None,
                SchedulerCeiling::new(200),
                false,
                None,
            ),
            Ok(None)
        );

        tracker
            .mark_halted(2)
            .unwrap_or_else(|error| panic!("vCPU 2 should halt: {error}"));
        let plan = match compute_all_halted_idle_wake_plan(
            &tracker,
            10,
            0,
            &reports,
            None,
            SchedulerCeiling::new(200),
            false,
            None,
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) => panic!("all halted should produce an idle wake plan"),
            Err(error) => panic!("all-halted idle wake should plan: {error}"),
        };

        assert_eq!(plan.timer_deadline_icount(), Some(80));
        assert_eq!(plan.desired_wake_icount(), 80);
        assert_eq!(plan.cause(), IdleWakeCause::TimerDeadline);
    }

    #[test]
    fn all_halted_idle_wake_validates_complete_deadline_reports() {
        let mut tracker = VcpuHaltTracker::new(2)
            .unwrap_or_else(|error| panic!("halt tracker should validate: {error}"));
        tracker
            .mark_halted(0)
            .unwrap_or_else(|error| panic!("vCPU 0 should halt: {error}"));
        tracker
            .mark_halted(1)
            .unwrap_or_else(|error| panic!("vCPU 1 should halt: {error}"));

        assert_eq!(
            compute_all_halted_idle_wake_plan(
                &tracker,
                10,
                0,
                &[PerVcpuDeadlineReport::new(
                    0,
                    ExactDeadlineReport::NoArmedTimer,
                )],
                None,
                SchedulerCeiling::new(20),
                false,
                None,
            ),
            Err(RoundRobinError::DeadlineAggregation(
                ExactDeadlineError::MissingVcpuDeadline { vcpu_id: 1 },
            ))
        );
    }
}
