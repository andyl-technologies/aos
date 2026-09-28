//! Host-retained kernel readback for the closed original FUSE worker role.
//!
//! This owner starts only a typed worker specification and retains the exact
//! manager invocation, pidfd, and independent cgroup. Those observations do
//! not establish Mount's original FUSE OFD, attachment, lease, or private record
//! channel. Only the held cross-owner composition may join them to a consumer.

use std::os::fd::BorrowedFd;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_systemd::{
    ExactStartError, FuseWorkerUnitNameV1, FuseWorkerUnitObservationV1, FuseWorkerUnitSpecV1,
    JobResult, SystemdClient,
};

use crate::{HostError, Result};

/// Retains one actual worker invocation without conferring consumer authority.
///
/// There is no constructor from a received pidfd or scalar launch receipt.
/// The only constructor performs the real fixed Host launch and repeated
/// manager/kernel readback. Recovery cannot reconstruct this live custody
/// from a journal row; lost custody requires explicit drain and reconciliation.
pub struct RetainedFuseWorkerHostLaunchV1 {
    name: FuseWorkerUnitNameV1,
    boot: KernelBootId,
    invocation: [u8; 16],
    process: PidFd,
    process_identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
}

impl RetainedFuseWorkerHostLaunchV1 {
    /// Launches one fixed worker under the protected caller's final effect guard.
    ///
    /// The guard must retain the original authenticated Host/Mount submission
    /// and image/environment seal through actual activation and this readback.
    /// This transport composition registers no broker method or worker listener.
    ///
    /// # Errors
    ///
    /// Returns an error for a pre-existing locator, denied final guard, failed
    /// launch, unavailable kernel inspection, foreign cgroup, changed invocation,
    /// or exited/replaced worker. A failure after submission is ambiguous and
    /// must keep the caller's reservation and descriptor/pin escrow intact.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `before_effect` before manager submission.
    pub async fn launch_guarded(
        systemd: &SystemdClient,
        cgroup_root: &CgroupV2Root,
        spec: &FuseWorkerUnitSpecV1,
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<Self> {
        let boot = KernelBootId::current().map_err(kernel_error)?;
        if systemd
            .observe_fuse_worker_unit_v1(spec.name())
            .await
            .map_err(manager_error)?
            .is_some()
        {
            return Err(HostError::Fence("FUSE worker locator already exists"));
        }

        let job = systemd
            .start_fuse_worker_unit_guarded_v1(spec, before_effect)
            .await
            .map_err(|error| match error {
                ExactStartError::Guard(error) => error,
                ExactStartError::Systemd(error) => manager_error(error),
            })?;
        if job.result != JobResult::Done {
            return Err(HostError::Worker(
                "FUSE worker start did not complete".to_owned(),
            ));
        }

        let observation = observe_running(systemd, spec.name()).await?;
        let invocation = observation
            .invocation_id
            .ok_or_else(|| HostError::Worker("FUSE worker invocation is absent".to_owned()))?;
        let pid = observation
            .main_pid
            .ok_or_else(|| HostError::Worker("FUSE worker leader is absent".to_owned()))?;
        let process = PidFd::open(pid).map_err(kernel_error)?;
        let cgroup_path = spec.name().cgroup_path();
        let relative = cgroup_path
            .as_str()
            .strip_prefix('/')
            .ok_or_else(|| HostError::Worker("FUSE worker cgroup is noncanonical".to_owned()))?;
        let cgroup = cgroup_root
            .resolve(Path::new(relative))
            .map_err(kernel_error)?;
        cgroup
            .verify_exact_membership(&process)
            .map_err(kernel_error)?;
        let process_identity = process.process_identity().map_err(kernel_error)?;

        let retained = Self {
            name: spec.name().clone(),
            boot,
            invocation,
            process,
            process_identity,
            cgroup,
        };
        retained.recheck(systemd).await?;
        Ok(retained)
    }

    /// Rechecks the same original invocation, live process, boot, and cgroup.
    ///
    /// # Errors
    ///
    /// Returns an error when any retained kernel object or manager identity
    /// changes. This cannot establish Mount/Controller currentness or authorize
    /// a new backing grant without their independently retained held cut.
    pub async fn recheck(&self, systemd: &SystemdClient) -> Result<()> {
        if KernelBootId::current().map_err(kernel_error)? != self.boot {
            return Err(HostError::Fence("FUSE worker kernel boot changed"));
        }
        self.cgroup.validate_current().map_err(kernel_error)?;
        self.cgroup
            .verify_exact_membership(&self.process)
            .map_err(kernel_error)?;
        if self.process.process_identity().map_err(kernel_error)? != self.process_identity {
            return Err(HostError::Fence("FUSE worker process identity changed"));
        }

        let observed = observe_running(systemd, &self.name).await?;
        if observed.invocation_id != Some(self.invocation)
            || observed.main_pid.map(|pid| pid.get()) != Some(self.process_identity.pid())
            || observed.cgroup != Some(self.name.cgroup_path())
        {
            return Err(HostError::Fence("FUSE worker manager identity changed"));
        }
        self.cgroup
            .verify_exact_membership(&self.process)
            .map_err(kernel_error)?;
        if !self.process.is_alive().map_err(kernel_error)? {
            return Err(HostError::Fence("FUSE worker exited during readback"));
        }

        Ok(())
    }

    /// Borrows the original launch-observed worker pidfd.
    #[must_use]
    pub const fn process(&self) -> &PidFd {
        &self.process
    }

    /// Borrows the original independently confined worker cgroup object.
    #[must_use]
    pub fn cgroup(&self) -> BorrowedFd<'_> {
        self.cgroup.as_fd()
    }

    /// Returns the original boot-local process identity for exact comparisons.
    #[must_use]
    pub const fn process_identity(&self) -> PidFdProcessIdentity {
        self.process_identity
    }

    /// Returns the actual first-launch invocation for exact session joining.
    #[must_use]
    pub const fn invocation(&self) -> [u8; 16] {
        self.invocation
    }
}

async fn observe_running(
    systemd: &SystemdClient,
    name: &FuseWorkerUnitNameV1,
) -> Result<FuseWorkerUnitObservationV1> {
    let observed = systemd
        .observe_fuse_worker_unit_v1(name)
        .await
        .map_err(manager_error)?
        .ok_or_else(|| HostError::Worker("FUSE worker unit is absent".to_owned()))?;
    if observed.active_state != "active" || observed.sub_state != "running" {
        return Err(HostError::Worker("FUSE worker is not running".to_owned()));
    }

    Ok(observed)
}

fn manager_error(error: aos_systemd::Error) -> HostError {
    HostError::Worker(format!("FUSE worker manager readback failed: {error}"))
}

fn kernel_error(error: aos_sandbox_linux::Error) -> HostError {
    HostError::Worker(format!("FUSE worker kernel readback failed: {error}"))
}
