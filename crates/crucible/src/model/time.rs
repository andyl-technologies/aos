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
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] if the obsolete QEMU
    /// nanosecond shift is nonzero.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        validate_fixed_shift(shift)?;
        Ok(VirtualInstant {
            ticks: self.retired,
        })
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
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] if the obsolete QEMU
    /// nanosecond shift is nonzero.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        Icount {
            retired: self.ticks,
        }
        .to_virtual(shift)
    }
}

/// The fixed QEMU CLI shift, which must be zero in the sim accelerator.
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
pub struct Shift {
    /// The QEMU CLI shift; only zero is admitted.
    pub bits: u8,
}

impl Shift {
    /// Builds a fixed icount shift.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] unless `bits` is zero.
    pub fn new(bits: u8) -> Result<Self, TimeConversionError> {
        let shift = Self { bits };
        validate_fixed_shift(shift)?;
        Ok(shift)
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

    /// Converts this virtual-time point to the containing instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] if `shift` is nonzero.
    pub fn to_icount_floor(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        validate_fixed_shift(shift)?;
        Ok(Icount {
            retired: self.ticks,
        })
    }

    /// Converts this virtual-time point to the first instruction boundary at or after it.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] if `shift` is nonzero.
    pub fn to_icount_ceil(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        validate_fixed_shift(shift)?;
        Ok(Icount {
            retired: self.ticks,
        })
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
    /// The QEMU shift is not the fixed zero required by sim mode.
    InvalidShift {
        /// The invalid shift.
        shift: Shift,
    },
    /// The converted virtual-time point would overflow `u64`.
    VirtualTimeOverflow {
        /// The input instruction count.
        icount: Icount,
        /// The fixed shift.
        shift: Shift,
    },
}

impl fmt::Display for TimeConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NanosecondOverflow { nanos } => {
                write!(f, "{nanos} nanoseconds exceeds the simulation tick range")
            }
            Self::InvalidShift { shift } => {
                write!(
                    f,
                    "icount shift {} is not the fixed zero required by sim mode",
                    shift.bits
                )
            }
            Self::VirtualTimeOverflow { icount, shift } => write!(
                f,
                "virtual time overflow for icount {} with shift {}",
                icount.retired, shift.bits
            ),
        }
    }
}

impl Error for TimeConversionError {}

pub(super) fn validate_fixed_shift(shift: Shift) -> Result<(), TimeConversionError> {
    if shift.bits == 0 {
        Ok(())
    } else {
        Err(TimeConversionError::InvalidShift { shift })
    }
}
