//! Owns one accepted whole-process operational reservation before actors exist.
//!
//! The envelope is a reservation quantity, not an allocator-demand observation.
//! A completed original may lend process-scoped leases to another thread in the
//! same process. Those leases never create Source, node or execution authority.
//! Address-space enforcement does not bound kernel/socket/page-cache allocations,
//! disk backing or child memory; their actual controls remain independent.

use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

static ISSUED_PROCESS: AtomicU32 = AtomicU32::new(0);

fn claim_issuance(latch: &AtomicU32, process: u32) -> Result<(), LinuxProcessSupervisorError> {
    if process == 0 {
        return Err(LinuxProcessSupervisorError::ForeignAuthority);
    }
    latch
        .compare_exchange(0, process, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| LinuxProcessSupervisorError::DuplicateOperation)
}

struct Original {
    process: u32,
    policy: LinuxProcessLimits,
    installed: Option<LinuxProcessLimits>,
    supervisor: Option<LinuxProcessSupervisor>,
    failure: Option<LinuxProcessSupervisorError>,
    revoked: AtomicBool,
}

impl Original {
    fn authenticate(&self) -> Result<(), LinuxProcessSupervisorError> {
        if self.process != std::process::id() || self.revoked.load(Ordering::Acquire) {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        if self.installed.is_none() {
            return Err(LinuxProcessSupervisorError::OutstandingObligations);
        }
        let result = self
            .supervisor
            .as_ref()
            .ok_or(LinuxProcessSupervisorError::OutstandingObligations)?
            .authenticate_process_current();
        if result.is_err() {
            self.revoked.store(true, Ordering::Release);
        }
        result
    }
}

/// Retains one nonrenewable whole-parent operational reservation.
///
/// The trusted deployment entry accepts the explicit operator policy and calls
/// this owner before runtime, actor, manifest or Source construction. Its CPU,
/// address-space and descriptor envelope includes every actor in that process;
/// it is neither a worker subpool nor a promise of available physical RAM.
#[must_use = "retain the original deployment reservation through actor teardown"]
pub struct OriginalDeploymentResourceReservation {
    original: Arc<Original>,
}

impl OriginalDeploymentResourceReservation {
    /// Retains and installs the accepted policy once before actors exist.
    ///
    /// The output is populated before preparation and irreversible installation.
    /// An attempted process cannot reissue this reservation after failure/drop.
    /// The operator acceptance must come from the actual trusted service entry;
    /// limit DATA or calling this API alone grants no Source semantic credit.
    ///
    /// # Errors
    /// Refuses occupied output, repeated issuance, invalid birth phase/policy,
    /// failed kernel setup or changed enforcement. Partial originals remain in
    /// `output`, including the original closed failure.
    pub fn install_before_actors_into(
        output: &mut Option<Self>,
        policy: LinuxProcessLimits,
    ) -> Result<(), LinuxProcessSupervisorError> {
        if output.is_some() {
            return Err(LinuxProcessSupervisorError::DuplicateOperation);
        }
        let process = std::process::id();
        claim_issuance(&ISSUED_PROCESS, process)?;
        *output = Some(Self {
            original: Arc::new(Original {
                process,
                policy,
                installed: None,
                supervisor: None,
                failure: None,
                revoked: AtomicBool::new(false),
            }),
        });
        let owner = output
            .as_mut()
            .ok_or(LinuxProcessSupervisorError::OutstandingObligations)?;
        let original = Arc::get_mut(&mut owner.original)
            .ok_or(LinuxProcessSupervisorError::OutstandingObligations)?;
        let result = (|| {
            LinuxProcessSupervisor::prepare_before_actors_into(&mut original.supervisor, &policy)?;
            let supervisor = original
                .supervisor
                .as_mut()
                .ok_or(LinuxProcessSupervisorError::OutstandingObligations)?;
            supervisor.install_prepared_before_actors()?;
            let installed = supervisor.installed_target_data()?;
            if installed.cpu_seconds > policy.cpu_seconds
                || installed.address_space_bytes > policy.address_space_bytes
                || installed.descriptors > policy.descriptors
            {
                return Err(LinuxProcessSupervisorError::ForeignAuthority);
            }
            original.installed = Some(installed);
            original.authenticate()
        })();
        if let Err(error) = result {
            original.failure = Some(error);
            original.revoked.store(true, Ordering::Release);
        }
        result
    }

    /// Authenticates the same completed envelope from the actual current process.
    ///
    /// The reservation is process-scoped after its single-threaded installation;
    /// it does not claim the bootstrap thread is still the current actor.
    ///
    /// # Errors
    /// Refuses incomplete/revoked/foreign ownership or changed kernel/proc facts.
    pub fn authenticate_current(&self) -> Result<(), LinuxProcessSupervisorError> {
        self.original.authenticate()
    }

    /// Lends the completed original to an actual actor in the same process.
    ///
    /// # Errors
    /// Refuses any incomplete, revoked, foreign or changed reservation.
    pub fn lease(&self) -> Result<DeploymentResourceLease, LinuxProcessSupervisorError> {
        self.authenticate_current()?;
        Ok(DeploymentResourceLease {
            original: self.original.clone(),
        })
    }

    /// Borrows the original reservation for one repeatable whole-holder census.
    ///
    /// Reading this context neither spends nor renews the process reservation.
    ///
    /// # Errors
    /// Refuses incomplete/revoked/foreign ownership or changed enforcement.
    pub fn read_context(
        &self,
    ) -> Result<DeploymentResourceReadContext<'_>, LinuxProcessSupervisorError> {
        self.authenticate_current()?;
        Ok(DeploymentResourceReadContext { owner: self })
    }

    /// Reports the actual installed whole-process reservation quantities as DATA.
    ///
    /// Stricter inherited ceilings remain stricter than the accepted policy.
    ///
    /// # Errors
    /// Refuses a prefix that has not completed the original installation.
    pub fn reserved_policy_data(&self) -> Result<LinuxProcessLimits, LinuxProcessSupervisorError> {
        self.original
            .installed
            .ok_or(LinuxProcessSupervisorError::OutstandingObligations)
    }

    /// Reports the operator-accepted restriction, not an installed reservation.
    pub fn accepted_policy_data(&self) -> LinuxProcessLimits {
        self.original.policy
    }

    /// Borrows the first actual closed preparation/installation failure.
    pub fn failure_data(&self) -> Option<LinuxProcessSupervisorError> {
        self.original.failure
    }

    /// Permanently revokes new acceptance while actual cleanup retains its owners.
    pub fn revoke(&self) {
        self.original.revoked.store(true, Ordering::Release);
    }
}

impl Drop for OriginalDeploymentResourceReservation {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Retains the private same-original process reservation across actor handoff.
///
/// Cloning the lease retains one original envelope; it issues no second budget.
/// There is no DATA, path, hash or deserialization constructor.
#[derive(Clone)]
pub struct DeploymentResourceLease {
    original: Arc<Original>,
}

impl DeploymentResourceLease {
    /// Authenticates the same original process and unchanged enforced envelope.
    ///
    /// # Errors
    /// Refuses incomplete/revoked/foreign ownership or changed kernel/proc facts.
    pub fn authenticate_current(&self) -> Result<(), LinuxProcessSupervisorError> {
        self.original.authenticate()
    }

    /// Matches an actual whole-holder read to its original reservation owner.
    ///
    /// # Errors
    /// Refuses another original or changed/revoked process enforcement.
    pub fn authenticate_in(
        &self,
        context: &DeploymentResourceReadContext<'_>,
    ) -> Result<(), LinuxProcessSupervisorError> {
        if !Arc::ptr_eq(&self.original, &context.owner.original) {
            return Err(LinuxProcessSupervisorError::ForeignAuthority);
        }
        self.authenticate_current()
    }
}

/// Borrows one original reservation through an entire whole-holder conjunction.
///
/// The context contains no public caller-provided byte total or authority flag.
pub struct DeploymentResourceReadContext<'a> {
    owner: &'a OriginalDeploymentResourceReservation,
}

impl DeploymentResourceReadContext<'_> {
    /// Reports the original whole-process budget, not observed requested bytes.
    ///
    /// # Errors
    /// Refuses incomplete original installation; read-only access grants no budget.
    pub fn reserved_policy_data(&self) -> Result<LinuxProcessLimits, LinuxProcessSupervisorError> {
        self.owner.reserved_policy_data()
    }
}

#[cfg(test)]
#[path = "reservation/tests.rs"]
mod tests;
