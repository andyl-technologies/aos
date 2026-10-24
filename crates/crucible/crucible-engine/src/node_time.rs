//! Scheduler-local mapping between backend counters and logical time.
//!
//! A replacement backend may begin at a different node-local counter
//! after restore. [`NodeTimeMapping`] preserves the committed logical-time
//! boundary while rebasing that physical counter origin. Guest clock faults are
//! applied by the signal-driven QEMU adapter and never alter this scheduler map.

use crate::{NodeCounter, SimInstant, TimeConversionError};

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
    pub fn logical_time(self, counter: NodeCounter) -> Result<SimInstant, TimeConversionError> {
        let raw_time = counter.to_virtual();
        let raw_anchor = self.anchor_counter.to_virtual();
        let ticks = if raw_time >= raw_anchor {
            self.anchor_time
                .ticks
                .checked_add(raw_time.ticks - raw_anchor.ticks)
        } else {
            self.anchor_time
                .ticks
                .checked_sub(raw_anchor.ticks - raw_time.ticks)
        }
        .ok_or(TimeConversionError::VirtualTimeOverflow {
            icount: crate::Icount {
                retired: counter.ticks,
            },
        })?;
        Ok(SimInstant { ticks })
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
    ) -> Result<NodeCounter, TimeConversionError> {
        if target <= self.anchor_time {
            return Ok(self.anchor_counter);
        }
        let delta = target.ticks - self.anchor_time.ticks;
        let ticks = self.anchor_counter.ticks.checked_add(delta).ok_or(
            TimeConversionError::VirtualTimeOverflow {
                icount: crate::Icount { retired: u64::MAX },
            },
        )?;
        Ok(NodeCounter { ticks })
    }

    /// Computes the greatest counter whose projection does not pass `target`.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the projection scale, resulting
    /// counter, or anchored logical time cannot be represented.
    pub fn counter_for_logical_time_floor(
        self,
        target: SimInstant,
    ) -> Result<NodeCounter, TimeConversionError> {
        let ticks = if target >= self.anchor_time {
            let delta = target.ticks - self.anchor_time.ticks;
            self.anchor_counter.ticks.checked_add(delta)
        } else {
            let delta = self.anchor_time.ticks - target.ticks;
            self.anchor_counter.ticks.checked_sub(delta)
        }
        .ok_or(TimeConversionError::VirtualTimeOverflow {
            icount: crate::Icount {
                retired: self.anchor_counter.ticks,
            },
        })?;

        let counter = NodeCounter { ticks };
        // A counter can fit even when its anchored logical-time projection
        // falls before the virtual epoch. Validate that projection here so a
        // caller never receives a counter outside this mapping's domain.
        let _ = self.logical_time(counter)?;

        Ok(counter)
    }
}

impl Default for NodeTimeMapping {
    fn default() -> Self {
        Self::IDENTITY
    }
}
