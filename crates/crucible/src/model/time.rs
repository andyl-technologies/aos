//! Exact simulation ticks, retired instructions, and nanosecond projections.

use super::*;

/// A virtual time value used by the execution-model signatures.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct VirtualTime {
    /// The canonical virtual-time tick.
    pub ticks: u64,
}

/// The fixed number of exact simulation ticks in one guest nanosecond.
pub const SIM_TICKS_PER_NS: u64 = 8;

/// One exact 125 picosecond coordinate on the simulation timeline.
pub type SimTick = u64;

/// An instruction-count value used by backend and preemption signatures.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Icount {
    /// The retired-instruction count.
    pub retired: u64,
}

impl Icount {
    /// Converts this instruction count into a virtual-time point.
    #[must_use]
    pub fn to_virtual(self) -> VirtualInstant {
        VirtualInstant {
            ticks: self.retired,
        }
    }
}

/// A monotone per-node counter projected onto the shared virtual timeline.
///
/// VM nodes construct this from retired guest instructions; deterministic I/O
/// sub-nodes construct it from their model-owned completion counter. Both use
/// the same exact-tick projection.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct NodeCounter {
    /// The node-local counter value.
    pub ticks: u64,
}

impl NodeCounter {
    /// Converts a VM retired-instruction count into a scheduler node counter.
    #[must_use]
    pub fn from_icount(icount: Icount) -> Self {
        Self {
            ticks: icount.retired,
        }
    }

    /// Converts this node-local counter into a shared virtual-time point.
    #[must_use]
    pub fn to_virtual(self) -> VirtualInstant {
        Icount {
            retired: self.ticks,
        }
        .to_virtual()
    }
}

/// A point on the shared virtual timeline.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct VirtualInstant {
    /// Exact simulation ticks since Crucible's fixed virtual epoch.
    pub ticks: u64,
}

impl VirtualInstant {
    /// The fixed virtual-time epoch.
    pub const EPOCH: Self = Self { ticks: 0 };

    /// The maximum representable virtual-time point.
    pub const MAX: Self = Self { ticks: u64::MAX };

    /// Converts an integer guest nanosecond timestamp to its exact tick boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::NanosecondOverflow`] if it exceeds the
    /// representable simulation timeline.
    pub fn from_nanoseconds(nanos: u64) -> Result<Self, TimeConversionError> {
        let ticks = nanos
            .checked_mul(SIM_TICKS_PER_NS)
            .ok_or(TimeConversionError::NanosecondOverflow { nanos })?;
        Ok(Self { ticks })
    }

    /// Returns the guest-visible integer nanoseconds at this exact tick.
    #[must_use]
    pub const fn nanoseconds_floor(self) -> u64 {
        self.ticks / SIM_TICKS_PER_NS
    }

    /// Returns the saturating non-negative span since `earlier`.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> SimDuration {
        SimDuration {
            ticks: self.ticks.saturating_sub(earlier.ticks),
        }
    }

    /// Applies a signed virtual-time offset, saturating at the virtual epoch.
    #[must_use]
    pub fn with_skew(self, offset: SimOffset) -> Self {
        let shifted = i128::from(self.ticks) + i128::from(offset.ticks);
        if shifted <= 0 {
            Self::EPOCH
        } else if shifted > i128::from(u64::MAX) {
            Self { ticks: u64::MAX }
        } else {
            Self {
                ticks: shifted as u64,
            }
        }
    }
}

impl ops::Add<SimDuration> for VirtualInstant {
    type Output = Self;

    fn add(self, duration: SimDuration) -> Self::Output {
        Self {
            ticks: self.ticks.saturating_add(duration.ticks),
        }
    }
}

/// Alias for the shared-timeline reading of a point.
pub type SimInstant = VirtualInstant;

/// An unsigned virtual-time span.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SimDuration {
    /// Exact simulation ticks in the span.
    pub ticks: u64,
}

impl SimDuration {
    /// Converts a whole-nanosecond duration to exact simulation ticks.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::NanosecondOverflow`] if the duration
    /// cannot fit in the tick coordinate.
    pub fn from_nanoseconds(nanos: u64) -> Result<Self, TimeConversionError> {
        let ticks = nanos
            .checked_mul(SIM_TICKS_PER_NS)
            .ok_or(TimeConversionError::NanosecondOverflow { nanos })?;
        Ok(Self { ticks })
    }

    /// Converts an exact tick span to whole nanoseconds without discarding phase.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::SubNanosecondDuration`] when the span is
    /// not an integer number of nanoseconds.
    pub fn nanoseconds_exact(self) -> Result<u64, TimeConversionError> {
        if !self.ticks.is_multiple_of(SIM_TICKS_PER_NS) {
            return Err(TimeConversionError::SubNanosecondDuration { ticks: self.ticks });
        }
        Ok(self.ticks / SIM_TICKS_PER_NS)
    }
}

impl ops::Add for SimDuration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            ticks: self.ticks.saturating_add(rhs.ticks),
        }
    }
}

impl ops::Mul<u64> for SimDuration {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self {
            ticks: self.ticks.saturating_mul(rhs),
        }
    }
}

/// A signed virtual-time offset used for configured clock skew.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimOffset {
    /// Signed exact simulation ticks in the offset.
    pub ticks: i64,
}

/// A virtual-time conversion error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeConversionError {
    /// An integer nanosecond timestamp or span exceeds the tick coordinate.
    NanosecondOverflow {
        /// The unrepresentable nanosecond value.
        nanos: u64,
    },
    /// An exact tick duration cannot be represented as whole nanoseconds.
    SubNanosecondDuration {
        /// The exact duration that would lose phase.
        ticks: u64,
    },
    /// The converted virtual-time point would overflow `u64`.
    VirtualTimeOverflow {
        /// The input instruction count.
        icount: Icount,
    },
}

impl fmt::Display for TimeConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NanosecondOverflow { nanos } => {
                write!(f, "{nanos} nanoseconds exceeds the simulation tick range")
            }
            Self::SubNanosecondDuration { ticks } => {
                write!(f, "{ticks} ticks is not a whole-nanosecond duration")
            }
            Self::VirtualTimeOverflow { icount } => {
                write!(f, "virtual time overflow for icount {}", icount.retired)
            }
        }
    }
}

impl Error for TimeConversionError {}
