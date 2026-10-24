//! Lossless preparation-time mapping of the existing QEMU clock lattice.
//!
//! These conversions describe data. They cannot establish a native stop,
//! pending-source closure, common phase, or permission to submit a quantum.

use crucible_engine::{Icount, SIM_TICKS_PER_INSTRUCTION, VirtualTime};
use crucible_node_format::{Phase, Position};
use crucible_qemu_host::QemuLogicalTimeCalibration;

use super::{OperationFailure, refusal};

/// Retains the fixed instruction scale and reported idle-time bias.
///
/// Logical time comes from the plugin's coherent calibration. Recomputing it
/// from raw retirement would discard idle jumps. The supplied calibration is
/// data, and this type has no native authority or serializer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSimClockLattice {
    logical: u64,
    raw: u64,
    bias: u64,
}

impl QemuSimClockLattice {
    /// Checks a reported calibration without rounding or changing the 50 ps scale.
    ///
    /// # Errors
    /// Refuses raw retirement multiplication overflow or logical time below it.
    pub fn from_calibration(
        calibration: QemuLogicalTimeCalibration,
    ) -> Result<Self, OperationFailure> {
        let bias = calibration
            .offset()
            .map_err(|_| refusal("QEMU reported logical/raw calibration is invalid"))?;

        Ok(Self {
            logical: calibration.logical_icount,
            raw: calibration.raw_icount,
            bias,
        })
    }

    /// Borrows the exact reported logical coordinate and original raw retirement.
    pub fn reported(&self) -> QemuLogicalTimeCalibration {
        QemuLogicalTimeCalibration {
            logical_icount: self.logical,
            raw_icount: self.raw,
        }
    }

    /// Projects raw retirement on the same reported lattice with checked arithmetic.
    ///
    /// # Errors
    /// Refuses multiplication or bias-addition overflow.
    pub fn logical_time(&self, retired: u64) -> Result<VirtualTime, OperationFailure> {
        let ticks = retired
            .checked_mul(SIM_TICKS_PER_INSTRUCTION)
            .and_then(|ticks| ticks.checked_add(self.bias))
            .ok_or_else(|| refusal("QEMU raw retirement cannot be represented in picoseconds"))?;

        Ok(VirtualTime { ticks })
    }

    /// Maps a supplied common boundary to an exact legacy logical ceiling.
    ///
    /// The legacy channel's `Icount.retired` ceiling carries logical picoseconds,
    /// as in the existing QemuNodeSet step path. It is not a raw retired count.
    /// This conversion does not turn a legacy observation into a common Position.
    ///
    /// # Errors
    /// Refuses a microstep, a phase other than BoundaryControl, a coordinate
    /// before the reported calibration, or a coordinate off its 50 ps lattice.
    pub fn legacy_ceiling(&self, boundary: Position) -> Result<Icount, OperationFailure> {
        if boundary.microstep.get() != 0 || boundary.phase != Phase::BoundaryControl {
            return Err(refusal(
                "QEMU legacy ceiling cannot encode the supplied full phase",
            ));
        }
        let logical = boundary.time_ps.get();
        if logical < self.logical
            || logical
                .checked_sub(self.bias)
                .is_none_or(|scaled| scaled % SIM_TICKS_PER_INSTRUCTION != 0)
        {
            return Err(refusal(
                "QEMU common boundary is before or off the reported lattice",
            ));
        }

        Ok(Icount { retired: logical })
    }
}
