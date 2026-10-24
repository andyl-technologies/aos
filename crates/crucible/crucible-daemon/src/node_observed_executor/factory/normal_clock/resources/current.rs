//! Delegates the original Clock bounded census to the shared L2 algorithm.

use super::*;
use crucible_host_resources::{LinuxProcessCeilingsData, LinuxProcessSupervisorError};

pub(super) fn authenticate(ceilings: ProcessCeilings) -> Result<(), RuntimeError> {
    LinuxProcessCeilingsData {
        cpu: ceilings.cpu,
        address_space: ceilings.address_space,
        descriptors: ceilings.descriptors,
    }
    .authenticate_existing()
    .map_err(|error| match error {
        LinuxProcessSupervisorError::DuplicateOperation => RuntimeError::DuplicateOperation,
        LinuxProcessSupervisorError::OutstandingObligations => RuntimeError::OutstandingObligations,
        LinuxProcessSupervisorError::ForeignAuthority => RuntimeError::ForeignAuthority,
        LinuxProcessSupervisorError::ResourceLimit => RuntimeError::ResourceLimit,
        LinuxProcessSupervisorError::UnsupportedFacet => RuntimeError::UnsupportedFacet,
    })
}
