//! Computes simultaneous process subsets inside one admitted node envelope.
//!
//! This module performs accounting, not native admission. The staged CPU field
//! names a later execution phase; it never permits both generations to run.
//! Paging I/O is additive: a parked CPU supplies no proof of drained I/O.

use crucible_linux_resource::ram_policy::HostResourceVector;

use super::HostRamAdmissionError;

mod native_allowances;
pub use native_allowances::{HostRamProcessFamilyNativeAllowances, HostRamProcessNativeAllowance};

/// Checked initial and staged subsets of one complete family entitlement.
///
/// Metadata and staging remain independently limited subsets of their peaks.
/// Constructing this value grants no process, workspace, cgroup or phase owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamProcessFamilyPartition {
    envelope: HostResourceVector,
    initial: HostResourceVector,
    staged: Option<HostResourceVector>,
}

impl HostRamProcessFamilyPartition {
    /// Retains a single process inside its existing complete envelope.
    ///
    /// # Errors
    /// Refuses malformed peak/subset geometry or zero process allowances.
    pub fn single(envelope: HostResourceVector) -> Result<Self, HostRamAdmissionError> {
        validate_process(envelope)?;
        Ok(Self {
            envelope,
            initial: envelope,
            staged: None,
        })
    }

    /// Reserves a staged floor before assigning any spendable initial resources.
    ///
    /// All overlapping axes add. Only CPU is phased: the initial process owns
    /// the envelope's CPU allowance until an authenticated parked-parent handoff.
    /// The staged result names its later CPU requirement, not a second CPU grant.
    ///
    /// # Errors
    /// Refuses malformed floors, any overflowing or insufficient additive axis,
    /// or a phase whose CPU requirement exceeds the original envelope.
    pub fn with_staged(
        envelope: HostResourceVector,
        initial_floor: HostResourceVector,
        staged_floor: HostResourceVector,
    ) -> Result<Self, HostRamAdmissionError> {
        validate_process(envelope)?;
        validate_process(initial_floor)?;
        validate_process(staged_floor)?;
        if initial_floor.cpu_slots > envelope.cpu_slots
            || staged_floor.cpu_slots > envelope.cpu_slots
        {
            return Err(HostRamAdmissionError::contract(
                "family CPU phase exceeds its original allowance",
            ));
        }

        let mut initial = envelope;
        macro_rules! reserve {
            ($($axis:ident),+ $(,)?) => {$(
                initial.$axis = envelope.$axis.checked_sub(staged_floor.$axis)
                    .filter(|remaining| *remaining >= initial_floor.$axis)
                    .ok_or_else(|| HostRamAdmissionError::contract(
                        concat!("simultaneous family ", stringify!($axis), " exceeds its original allowance")
                    ))?;
            )+};
        }
        reserve!(
            resident_peak_bytes,
            backing_peak_bytes,
            metadata_bytes,
            staging_bytes,
            paging_io_slots,
            task_slots,
            file_descriptors
        );
        validate_process(initial)?;
        Ok(Self {
            envelope,
            initial,
            staged: Some(staged_floor),
        })
    }

    /// Returns the complete outer entitlement retained once for the family.
    pub const fn envelope(self) -> HostResourceVector {
        self.envelope
    }

    /// Returns the initial process allowance after reserving every staged axis.
    pub const fn initial(self) -> HostResourceVector {
        self.initial
    }

    /// Returns a prospective stage's requirements without activating its CPU.
    pub const fn staged(self) -> Option<HostResourceVector> {
        self.staged
    }

    /// Returns the staged reservation before an authenticated CPU handoff.
    ///
    /// Every additive obligation is retained before the initial launch. CPU is
    /// zero in escrow: this value cannot authorize a child to execute while its
    /// parent owns the family's CPU phase. I/O remains independently reserved.
    pub fn staged_escrow(self) -> Option<HostResourceVector> {
        self.staged.map(|mut resources| {
            resources.cpu_slots = 0;
            resources
        })
    }
}

fn validate_process(resources: HostResourceVector) -> Result<(), HostRamAdmissionError> {
    if resources.resident_peak_bytes == 0
        || resources.backing_peak_bytes == 0
        || resources.cpu_slots == 0
        || resources.task_slots == 0
        || resources.file_descriptors == 0
        || resources.paging_io_slots == 0
        || resources
            .metadata_bytes
            .checked_add(resources.staging_bytes)
            .is_none_or(|bytes| bytes > resources.resident_peak_bytes)
        || resources.staging_bytes > resources.backing_peak_bytes
    {
        return Err(HostRamAdmissionError::contract(
            "process family floor has invalid peak/subset geometry",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
