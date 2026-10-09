//! Conserves the private operator's original guest and external Source purposes.
//!
//! This account starts at the explicit operator boundary, before rootfs copying
//! or QEMU birth. The guest's twenty-GiB physical envelope contains its sixteen-
//! GiB actor; that actor is not charged a second time. External emulator and
//! helper Source has a separate required finite ceiling. Installed image floors
//! validate that ceiling without claiming to bound runtime allocation peaks.

const GUEST_RESIDENT_BYTES: u64 = 20 << 30;
const GUEST_BACKING_BYTES: u64 = 64 << 30;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AdmissionError {
    InvalidSource,
    Overflow,
    SourceFloor,
    Occupied,
}

/// Authored external purposes, supplied by the private immutable operator.
pub(super) struct ExternalSourceContract {
    pub resident_bytes: u64,
    pub backing_bytes: u64,
    pub tasks: u32,
    pub descriptors: u64,
}

/// One non-clone original reservation retained beside physical child custody.
pub(super) struct OriginalParentAccount {
    resident_ceiling: u64,
    backing_ceiling: u64,
    source: ExternalSourceContract,
    state: ReservationState,
}

#[derive(Debug, PartialEq, Eq)]
enum ReservationState {
    Admitted,
    Born,
    Quarantined,
    Reaped,
}

impl OriginalParentAccount {
    pub(super) fn source_contract(&self) -> &ExternalSourceContract {
        &self.source
    }

    pub(super) fn admit(source: ExternalSourceContract) -> Result<Self, AdmissionError> {
        if source.resident_bytes == 0
            || source.backing_bytes == 0
            || source.tasks == 0
            || source.descriptors == 0
        {
            return Err(AdmissionError::InvalidSource);
        }
        let resident_ceiling = GUEST_RESIDENT_BYTES
            .checked_add(source.resident_bytes)
            .ok_or(AdmissionError::Overflow)?;
        let backing_ceiling = GUEST_BACKING_BYTES
            .checked_add(source.backing_bytes)
            .ok_or(AdmissionError::Overflow)?;

        Ok(Self {
            resident_ceiling,
            backing_ceiling,
            source,
            state: ReservationState::Admitted,
        })
    }

    pub(super) fn verify_installed_floor(
        &self,
        mapped_bytes: u64,
        backing_bytes: u64,
        original_control_bytes: u64,
    ) -> Result<(), AdmissionError> {
        if mapped_bytes == 0 || backing_bytes == 0 {
            return Err(AdmissionError::SourceFloor);
        }
        let resident_floor = mapped_bytes
            .checked_add(original_control_bytes)
            .ok_or(AdmissionError::Overflow)?;
        if resident_floor > self.source.resident_bytes || backing_bytes > self.source.backing_bytes
        {
            return Err(AdmissionError::SourceFloor);
        }
        Ok(())
    }

    pub(super) const fn resident_ceiling(&self) -> u64 {
        self.resident_ceiling
    }

    pub(super) const fn backing_ceiling(&self) -> u64 {
        self.backing_ceiling
    }

    pub(super) const fn tasks(&self) -> u32 {
        self.source.tasks
    }

    pub(super) const fn descriptors(&self) -> u64 {
        self.source.descriptors
    }

    pub(super) const fn source_resident(&self) -> u64 {
        self.source.resident_bytes
    }

    pub(super) fn publish_birth(&mut self) -> Result<(), AdmissionError> {
        if self.state != ReservationState::Admitted {
            return Err(AdmissionError::Occupied);
        }
        self.state = ReservationState::Born;
        Ok(())
    }

    pub(super) fn quarantine(&mut self) {
        if self.state != ReservationState::Reaped {
            self.state = ReservationState::Quarantined;
        }
    }

    // Only the retained physical owner calls this after successful direct wait
    // AND process/storage retirement. An exit observation alone is insufficient.
    pub(super) fn record_physical_retirement(&mut self) {
        self.state = ReservationState::Reaped;
    }
}
