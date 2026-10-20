//! Retains original whole-process Linux ceilings before service actors exist.
//!
//! This is a deployment boundary for the entire coordinator, including future
//! library allocations and thread stacks. It is never an exclusive Source row,
//! native execution grant or quota for a child process.

use rustix::process::{Resource, Rlimit, getrlimit};
use std::thread::ThreadId;

#[path = "linux_process_supervisor/bootstrap.rs"]
mod bootstrap;
#[path = "linux_process_supervisor/current.rs"]
mod current;
pub use bootstrap::LinuxProcessSupervisor;

/// Restricts the whole process with explicit hard Linux resource ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxProcessLimits {
    /// Bounds aggregate process CPU time since process birth, in whole seconds.
    pub cpu_seconds: u64,
    /// Bounds existing and future mapped/reserved process address space.
    pub address_space_bytes: u64,
    /// Bounds existing descriptor indices and all future descriptor allocation.
    pub descriptors: u64,
}

/// Reports the exact kernel limit pairs as DATA, without a constructor grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxProcessCeilingsData {
    /// Contains the soft and hard aggregate CPU ceilings.
    pub cpu: Rlimit,
    /// Contains the soft and hard address-space ceilings.
    pub address_space: Rlimit,
    /// Contains the soft and hard descriptor ceilings.
    pub descriptors: Rlimit,
}

impl LinuxProcessCeilingsData {
    /// Reads the three current process-wide kernel ceilings.
    pub fn current() -> Self {
        Self {
            cpu: getrlimit(Resource::Cpu),
            address_space: getrlimit(Resource::As),
            descriptors: getrlimit(Resource::Nofile),
        }
    }

    /// Checks current mappings, CPU usage and every open descriptor index.
    ///
    /// The caller separately checks this DATA against the actual unchanged
    /// kernel limit pairs; only the original supervisor owns deployment setup.
    ///
    /// # Errors
    /// Refuses unbounded/zero limits, existing resources above them, unavailable
    /// proc inspection or malformed/overflowing inspection records.
    pub fn authenticate_existing(self) -> Result<(), LinuxProcessSupervisorError> {
        current::authenticate(self)
    }
}

/// Reports a closed deployment-boundary refusal without rendering input data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinuxProcessSupervisorError {
    /// The retained deployment output has already been used.
    #[error("process deployment operation was already attempted")]
    DuplicateOperation,
    /// Setup is incomplete or its original owner is unavailable.
    #[error("process deployment setup is incomplete")]
    OutstandingObligations,
    /// The actual process/thread, kernel ceilings or birth phase changed.
    #[error("process deployment original changed")]
    ForeignAuthority,
    /// Actual limits, existing resources, arithmetic or a kernel update refused.
    #[error("process deployment resource restriction refused")]
    ResourceLimit,
    /// Required bounded kernel/proc inspection is unavailable or unsupported.
    #[error("process deployment inspection is unavailable")]
    UnsupportedFacet,
}
