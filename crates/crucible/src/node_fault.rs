//! Node fault application helpers.
//!
//! This module owns the VM timing projection for RFC-0010 node faults. The
//! scheduler still orders work on a virtual-time axis derived from node
//! counters, but an active slowdown stretches that counter-to-time map from an
//! activation anchor. Clock skew is projected only for guest-visible time reads
//! and is never folded into scheduler ordering keys or RUN ceilings.

use crate::{
    ClockDriftRate, CombinedNodeFaults, FaultSlowdownFactorBasisPoints, NodeClockSkew, NodeCounter,
    Shift, SimInstant, TimeConversionError,
};

/// Effective VM timing faults for one scheduler node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeTimingFaults {
    /// The active slowdown factor applied after `anchor_counter`.
    pub slow_factor: FaultSlowdownFactorBasisPoints,
    /// The guest-visible clock skew applied after slowdown projection.
    pub clock_skew: NodeClockSkew,
    /// The counter at which the current projection was installed.
    pub anchor_counter: NodeCounter,
    /// The faulted virtual time observed at `anchor_counter`.
    pub anchor_time: SimInstant,
}

impl NodeTimingFaults {
    /// The identity timing projection.
    pub const IDENTITY: Self = Self {
        slow_factor: FaultSlowdownFactorBasisPoints::ONE,
        clock_skew: NodeClockSkew::PERFECT,
        anchor_counter: NodeCounter { ticks: 0 },
        anchor_time: SimInstant::EPOCH,
    };

    /// Projects `counter` onto the scheduler virtual-time axis after slowdown.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when `shift` is invalid, when the raw
    /// counter projection overflows, or when the anchored slowed projection would
    /// exceed the representable virtual-time range.
    pub fn faulted_virtual_time(
        self,
        counter: NodeCounter,
        shift: Shift,
    ) -> Result<SimInstant, TimeConversionError> {
        let raw_time = counter.to_virtual(shift)?;
        let raw_anchor = self.anchor_counter.to_virtual(shift)?;
        let denominator = u128::from(FaultSlowdownFactorBasisPoints::ONE.basis_points());
        let factor = u128::from(self.slow_factor.basis_points());

        if raw_time >= raw_anchor {
            let raw_delta = u128::from(raw_time.nanos - raw_anchor.nanos);
            let slowed_delta = raw_delta * denominator / factor;
            let slowed_delta = u64::try_from(slowed_delta).map_err(|_| {
                TimeConversionError::VirtualTimeOverflow {
                    icount: crate::Icount {
                        retired: counter.ticks,
                    },
                    shift,
                }
            })?;
            let nanos = self.anchor_time.nanos.checked_add(slowed_delta).ok_or(
                TimeConversionError::VirtualTimeOverflow {
                    icount: crate::Icount {
                        retired: counter.ticks,
                    },
                    shift,
                },
            )?;
            Ok(SimInstant { nanos })
        } else {
            let raw_delta = u128::from(raw_anchor.nanos - raw_time.nanos);
            let slowed_delta = raw_delta * denominator / factor;
            let slowed_delta = u64::try_from(slowed_delta).map_err(|_| {
                TimeConversionError::VirtualTimeOverflow {
                    icount: crate::Icount {
                        retired: counter.ticks,
                    },
                    shift,
                }
            })?;
            Ok(SimInstant {
                nanos: self.anchor_time.nanos.saturating_sub(slowed_delta),
            })
        }
    }

    /// Computes the first counter whose faulted projection reaches `target`.
    ///
    /// Targets at or before the anchor map to the anchor counter because the
    /// scheduler cannot move a VM counter backward after fault activation.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when `shift` is invalid, when the anchor
    /// projection overflows, or when the resulting counter cannot fit in `u64`.
    pub fn counter_for_faulted_virtual_time_ceil(
        self,
        target: SimInstant,
        shift: Shift,
    ) -> Result<NodeCounter, TimeConversionError> {
        if target <= self.anchor_time {
            return Ok(self.anchor_counter);
        }

        let scale = NodeCounter { ticks: 1 }.to_virtual(shift)?.nanos;
        let denominator = u128::from(FaultSlowdownFactorBasisPoints::ONE.basis_points());
        let factor = u128::from(self.slow_factor.basis_points());
        let faulted_delta = u128::from(target.nanos - self.anchor_time.nanos);
        let raw_delta = ceil_div(faulted_delta * factor, denominator);
        let counter_delta = ceil_div(raw_delta, u128::from(scale));
        let counter_delta =
            u64::try_from(counter_delta).map_err(|_| TimeConversionError::VirtualTimeOverflow {
                icount: crate::Icount { retired: u64::MAX },
                shift,
            })?;
        let ticks = self.anchor_counter.ticks.checked_add(counter_delta).ok_or(
            TimeConversionError::VirtualTimeOverflow {
                icount: crate::Icount { retired: u64::MAX },
                shift,
            },
        )?;
        Ok(NodeCounter { ticks })
    }

    /// Projects all scheduler and guest-visible timing readings for `counter`.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when raw counter projection, slowdown
    /// projection, or guest-visible clock-skew projection fails.
    pub fn project(
        self,
        counter: NodeCounter,
        shift: Shift,
    ) -> Result<NodeTimingProjection, TimeConversionError> {
        let unfaulted_time = counter.to_virtual(shift)?;
        let faulted_time = self.faulted_virtual_time(counter, shift)?;
        let guest_visible_time = self.clock_skew.guest_visible_time(faulted_time)?;
        Ok(NodeTimingProjection {
            counter,
            unfaulted_time,
            faulted_time,
            guest_visible_time,
            slow_factor: self.slow_factor,
            clock_skew: self.clock_skew,
        })
    }
}

impl Default for NodeTimingFaults {
    fn default() -> Self {
        Self::IDENTITY
    }
}

/// Timing projection for one VM counter under active node faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeTimingProjection {
    /// The VM node-local counter used for the projection.
    pub counter: NodeCounter,
    /// The original fixed-shift projection before node faults.
    pub unfaulted_time: SimInstant,
    /// The scheduler virtual-time point after slowdown stretching.
    pub faulted_time: SimInstant,
    /// The guest-visible time-of-day point after clock skew.
    pub guest_visible_time: SimInstant,
    /// The slowdown factor used for this projection.
    pub slow_factor: FaultSlowdownFactorBasisPoints,
    /// The clock skew used only for `guest_visible_time`.
    pub clock_skew: NodeClockSkew,
}

/// Builds anchored timing faults from combined node-fault effects.
///
/// `anchor_time` should be the node's current faulted scheduler time immediately
/// before replacing its timing projection. This preserves continuity when slow
/// faults activate, heal, or change factor while the VM has already advanced.
#[must_use]
pub fn node_timing_faults_from_combined_node(
    faults: &CombinedNodeFaults,
    anchor_counter: NodeCounter,
    anchor_time: SimInstant,
) -> NodeTimingFaults {
    NodeTimingFaults {
        slow_factor: faults
            .slow_factor
            .unwrap_or(FaultSlowdownFactorBasisPoints::ONE),
        clock_skew: NodeClockSkew {
            offset: faults.clock_skew,
            drift_rate: ClockDriftRate::ONE,
        },
        anchor_counter,
        anchor_time,
    }
}

/// Projects one node counter under active timing faults.
///
/// # Errors
///
/// Returns [`TimeConversionError`] when raw counter projection, slowdown
/// projection, or guest-visible clock-skew projection fails.
pub fn project_node_timing(
    counter: NodeCounter,
    shift: Shift,
    faults: NodeTimingFaults,
) -> Result<NodeTimingProjection, TimeConversionError> {
    faults.project(counter, shift)
}

const fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    if numerator == 0 {
        0
    } else {
        ((numerator - 1) / denominator) + 1
    }
}
