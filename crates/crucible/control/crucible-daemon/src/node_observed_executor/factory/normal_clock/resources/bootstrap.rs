//! Adapts the original Clock deployment API to shared process enforcement.
//!
//! The same single-threaded entry, irreversible hard-limit installation and
//! actual proc admission now belong to the generic L2 supervisor. This adapter
//! retains a failed prefix before returning the original closed RuntimeError.

use super::*;
use crucible_host_resources::{
    LinuxProcessLimits, LinuxProcessSupervisor, LinuxProcessSupervisorError,
};

/// Retains the original whole-process deployment transaction through failure.
#[must_use = "retain original aggregate process setup even after partial failure"]
pub struct OriginalClockProcessBootstrap {
    original: LinuxProcessSupervisor,
}

fn map_error(error: LinuxProcessSupervisorError) -> RuntimeError {
    match error {
        LinuxProcessSupervisorError::DuplicateOperation => RuntimeError::DuplicateOperation,
        LinuxProcessSupervisorError::OutstandingObligations => RuntimeError::OutstandingObligations,
        LinuxProcessSupervisorError::ForeignAuthority => RuntimeError::ForeignAuthority,
        LinuxProcessSupervisorError::ResourceLimit => RuntimeError::ResourceLimit,
        LinuxProcessSupervisorError::UnsupportedFacet => RuntimeError::UnsupportedFacet,
    }
}

impl OriginalClockProcessBootstrap {
    /// Lowers the same whole-daemon ceilings before actors or children exist.
    ///
    /// # Errors
    /// Preserves occupied-output, birth-phase, resource, kernel-update and exact
    /// readback refusals. A failed installed prefix remains in `slot`.
    pub fn install_before_actors_into(
        slot: &mut Option<Self>,
        limits: &ResourceLimits,
    ) -> Result<(), RuntimeError> {
        if slot.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let mut original = None;
        LinuxProcessSupervisor::prepare_before_actors_into(
            &mut original,
            &LinuxProcessLimits {
                cpu_seconds: limits.cpu_budget_ns.get() / 1_000_000_000,
                address_space_bytes: limits.memory_bytes.get(),
                descriptors: limits.descriptors.get(),
            },
        )
        .map_err(map_error)?;
        let original = original.ok_or(RuntimeError::OutstandingObligations)?;
        *slot = Some(Self { original });
        slot.as_mut()
            .ok_or(RuntimeError::OutstandingObligations)?
            .original
            .install_prepared_before_actors()
            .map_err(map_error)
    }

    /// Borrows original pre-update CPU, address-space and descriptor ceiling DATA.
    pub fn previous_ceiling_data(&self) -> [(Option<u64>, Option<u64>); 3] {
        self.original.previous_ceiling_data()
    }

    /// Authenticates the same completed original deployment without raising limits.
    ///
    /// # Errors
    /// Preserves incomplete, foreign and changed-kernel-limit refusals.
    pub fn authenticate_current(&self) -> Result<(), RuntimeError> {
        self.original.authenticate_current().map_err(map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_supervisor_refusals_keep_the_original_clock_error_classes() {
        for (actual, expected) in [
            (
                LinuxProcessSupervisorError::DuplicateOperation,
                RuntimeError::DuplicateOperation,
            ),
            (
                LinuxProcessSupervisorError::OutstandingObligations,
                RuntimeError::OutstandingObligations,
            ),
            (
                LinuxProcessSupervisorError::ForeignAuthority,
                RuntimeError::ForeignAuthority,
            ),
            (
                LinuxProcessSupervisorError::ResourceLimit,
                RuntimeError::ResourceLimit,
            ),
            (
                LinuxProcessSupervisorError::UnsupportedFacet,
                RuntimeError::UnsupportedFacet,
            ),
        ] {
            assert_eq!(map_error(actual), expected);
        }
    }
}
