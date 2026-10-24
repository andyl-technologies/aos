//! Borrows an actually occupied Target role before its physical cgroup exists.

use super::*;

/// Borrows the exact saved Target reservation for pre-Stop stage preparation.
///
/// The Source permit owns the actual epoch and Preparation. This view creates
/// neither a process nor a CPU handoff, and cannot outlive that move-only permit.
pub struct QemuForkTargetLogicalReservation<'a> {
    reservation: &'a original_roster::ForkTargetReservation,
    source: &'a Weak<NativeResourceState>,
    generation: u64,
}

impl LinuxQemuForkTargetPermit {
    /// Borrows the genuine logical role before Park/Stop or physical birth.
    ///
    /// # Errors
    /// Refuses consumed, foreign, changed, expired or already-born custody.
    pub fn borrow_logical_reservation(
        &self,
    ) -> Result<QemuForkTargetLogicalReservation<'_>, QemuVmRealizationError> {
        let reservation = self
            .reservation
            .as_ref()
            .ok_or_else(|| missing_authority("borrow retained logical Target reservation"))?;
        let generation = reservation
            .check_logical_reservation()
            .map_err(original_roster::original_error)?;
        let borrowed = QemuForkTargetLogicalReservation {
            reservation,
            source: &self.source,
            generation,
        };
        borrowed.check_current()?;
        Ok(borrowed)
    }
}

impl QemuForkTargetLogicalReservation<'_> {
    /// Returns the generation reserved by the actual Target journal.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Rechecks the same Source, epoch and saved current Target Preparation.
    ///
    /// # Errors
    /// Refuses Source retirement, generation changes or attempted physical birth.
    pub fn check_current(&self) -> Result<(), QemuVmRealizationError> {
        let source = self
            .source
            .upgrade()
            .ok_or_else(|| missing_authority("retain logical Target Source"))?;
        if !NativeResourceState::available(&source)
            || self
                .reservation
                .check_logical_reservation()
                .map_err(original_roster::original_error)?
                != self.generation
        {
            return Err(missing_authority(
                "match current logical Target reservation",
            ));
        }
        Ok(())
    }
}
