//! Scheduler-local mapping between backend counters and logical time.
//!
//! A replacement backend may begin at a different retired-instruction counter
//! after restore. [`NodeTimeMapping`] preserves the committed logical-time
//! boundary while rebasing that physical counter origin. Guest clock faults are
//! applied by the signal-driven QEMU adapter and never alter this scheduler map.

use crate::{NodeCounter, Shift, SimInstant, TimeConversionError};

/// Anchored mapping from one node's backend counter to scheduler logical time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeTimeMapping {
    /// Backend counter at the mapping anchor.
    pub anchor_counter: NodeCounter,
    /// Scheduler logical time at `anchor_counter`.
    pub anchor_time: SimInstant,
}

impl NodeTimeMapping {
    /// Identity mapping at scheduler genesis.
    pub const IDENTITY: Self = Self {
        anchor_counter: NodeCounter { ticks: 0 },
        anchor_time: SimInstant::EPOCH,
    };

    /// Projects `counter` onto scheduler logical time.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the counter projection or anchored
    /// logical-time arithmetic overflows.
    pub fn logical_time(
        self,
        counter: NodeCounter,
        shift: Shift,
    ) -> Result<SimInstant, TimeConversionError> {
        let raw_time = counter.to_virtual(shift)?;
        let raw_anchor = self.anchor_counter.to_virtual(shift)?;
        let nanos = if raw_time >= raw_anchor {
            self.anchor_time
                .nanos
                .checked_add(raw_time.nanos - raw_anchor.nanos)
        } else {
            self.anchor_time
                .nanos
                .checked_sub(raw_anchor.nanos - raw_time.nanos)
        }
        .ok_or(TimeConversionError::VirtualTimeOverflow {
            icount: crate::Icount {
                retired: counter.ticks,
            },
            shift,
        })?;
        Ok(SimInstant { nanos })
    }

    /// Computes the first counter whose projection reaches `target`.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the projection scale or resulting
    /// counter cannot be represented.
    pub fn counter_for_logical_time_ceil(
        self,
        target: SimInstant,
        shift: Shift,
    ) -> Result<NodeCounter, TimeConversionError> {
        if target <= self.anchor_time {
            return Ok(self.anchor_counter);
        }
        let scale = NodeCounter { ticks: 1 }.to_virtual(shift)?.nanos;
        let delta = target.nanos - self.anchor_time.nanos;
        let counter_delta = delta.div_ceil(scale);
        let ticks = self.anchor_counter.ticks.checked_add(counter_delta).ok_or(
            TimeConversionError::VirtualTimeOverflow {
                icount: crate::Icount { retired: u64::MAX },
                shift,
            },
        )?;
        Ok(NodeCounter { ticks })
    }

    /// Projects the current counter into a typed scheduler observation.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] under the same conditions as
    /// [`Self::logical_time`].
    pub fn project(
        self,
        counter: NodeCounter,
        shift: Shift,
    ) -> Result<NodeTimeProjection, TimeConversionError> {
        Ok(NodeTimeProjection {
            counter,
            logical_time: self.logical_time(counter, shift)?,
        })
    }
}

impl Default for NodeTimeMapping {
    fn default() -> Self {
        Self::IDENTITY
    }
}

/// Scheduler observation of one node counter and its logical-time projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeTimeProjection {
    /// Backend counter used for the observation.
    pub counter: NodeCounter,
    /// Scheduler logical time corresponding to `counter`.
    pub logical_time: SimInstant,
}
