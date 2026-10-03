//! Host-retained kernel readback for the closed original FUSE worker role.
//!
//! This owner starts only a typed worker specification and retains the exact
//! manager invocation, pidfd, and independent cgroup. Those observations do
//! not establish Mount's original FUSE OFD, attachment, lease, or private record
//! channel. Only the held cross-owner composition may join them to a consumer.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::fuse_worker_image::FixedFuseWorkerImageV1;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_systemd::FixedFuseWorkerPid1ClientV1;
use aos_systemd::{
    ExactStartError, FuseWorkerUnitNameV1, FuseWorkerUnitObservationV1, FuseWorkerUnitSpecV1,
    JobResult,
};

use crate::{HostError, Result};

const WORKER_CONTEXT: &[u8] = b"system_u:system_r:aos_filesystem_fuse_worker_t";
const MAXIMUM_CONTEXT_BYTES: usize = 256;

/// Retains one actual worker invocation without conferring consumer authority.
///
/// There is no constructor from a received pidfd or scalar launch receipt.
/// The only constructor performs the real fixed Host launch and repeated
/// manager/kernel readback. Recovery cannot reconstruct this live custody
/// from a journal row; lost custody requires explicit drain and reconciliation.
pub struct RetainedFuseWorkerHostLaunchV1 {
    name: FuseWorkerUnitNameV1,
    image: FixedFuseWorkerImageV1,
    boot: KernelBootId,
    invocation: [u8; 16],
    process: PidFd,
    process_identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
}

impl RetainedFuseWorkerHostLaunchV1 {
    /// Consumes four original roles and launches the independently pinned image.
    ///
    /// Roles are the original sealed plan, fresh FUSE connection, private record
    /// endpoint, and cancellation reader, in that exact order. Host opens its
    /// own fixed executable; no received executable descriptor is accepted.
    /// The guard must retain the original authenticated Host/Mount submission
    /// through actual activation and this readback; PID 1 retains its image and
    /// environment seal. These kernel observations do not certify fresh FUSE
    /// provenance or confer Mount/Controller/read authority.
    /// This transport composition registers no broker method or worker listener.
    /// It consumes and closes its role table before worker readback. The
    /// enclosing fixed dispatch must also finish and drop its original receive
    /// packet and transport copies before acknowledging preparation.
    ///
    /// # Errors
    ///
    /// Returns an error for a pre-existing locator, denied final guard, failed
    /// image admission, launch, unavailable kernel inspection, foreign cgroup,
    /// changed invocation,
    /// or exited/replaced worker. A failure after submission is ambiguous and
    /// must keep the caller's reservation and descriptor/pin escrow intact.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `before_effect` before manager submission.
    pub async fn launch_guarded(
        systemd: &FixedFuseWorkerPid1ClientV1,
        cgroup_root: &CgroupV2Root,
        name: FuseWorkerUnitNameV1,
        original_roles: [OwnedFd; 4],
        before_effect: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<Self> {
        let boot = KernelBootId::current().map_err(kernel_error)?;
        if systemd
            .observe_fuse_worker_unit_v1(&name)
            .await
            .map_err(manager_error)?
            .is_some()
        {
            return Err(HostError::Fence("FUSE worker locator already exists"));
        }

        let image = FixedFuseWorkerImageV1::open_fixed().map_err(kernel_error)?;
        let spec = FuseWorkerUnitSpecV1::new(
            name.clone(),
            [
                image.executable(),
                original_roles[0].as_fd(),
                original_roles[1].as_fd(),
                original_roles[2].as_fd(),
                original_roles[3].as_fd(),
            ],
        )
        .map_err(manager_error)?;

        // Close this function's received-role owners. The enclosing dispatcher
        // must separately complete its packet/message copy-close barrier.
        drop(original_roles);

        let job = {
            let mut final_guard = || {
                image.recheck().map_err(kernel_error)?;
                before_effect()
            };
            systemd
                .start_fuse_worker_unit_guarded_v1(&spec, &mut final_guard)
                .await
                .map_err(|error| match error {
                    ExactStartError::Guard(error) => error,
                    ExactStartError::Systemd(error) => manager_error(error),
                })?
        };

        // The executor inherited the role table. Close these local copies
        // before readback; the enclosing dispatch owns its receive-packet barrier.
        drop(spec);

        if job.result != JobResult::Done {
            return Err(HostError::Worker(
                "FUSE worker start did not complete".to_owned(),
            ));
        }

        let observation = observe_running(systemd, &name).await?;
        let invocation = observation
            .invocation_id
            .ok_or_else(|| HostError::Worker("FUSE worker invocation is absent".to_owned()))?;
        let pid = observation
            .main_pid
            .ok_or_else(|| HostError::Worker("FUSE worker leader is absent".to_owned()))?;
        let process = PidFd::open(pid).map_err(kernel_error)?;
        let cgroup_path = name.cgroup_path();
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
            name,
            image,
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
    pub async fn recheck(&self, systemd: &FixedFuseWorkerPid1ClientV1) -> Result<()> {
        self.image.recheck().map_err(kernel_error)?;
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

        // Socketpair peer labels describe creation, not the post-exec worker.
        // Read the actual pinned task SID between kernel/manager observations.
        require_worker_context(self.process_identity.pid())?;

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

        require_worker_context(self.process_identity.pid())?;
        if self.process.process_identity().map_err(kernel_error)? != self.process_identity {
            return Err(HostError::Fence("FUSE worker changed during MAC readback"));
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

fn require_worker_context(pid: u32) -> Result<()> {
    let descriptor = rustix::fs::open(
        format!("/proc/{pid}/attr/current"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(format!("cannot inspect FUSE worker SID: {error}")))?;
    let file = File::from(descriptor);
    let mut context = Vec::new();
    file.take((MAXIMUM_CONTEXT_BYTES + 1) as u64)
        .read_to_end(&mut context)
        .map_err(|error| HostError::Worker(format!("cannot read FUSE worker SID: {error}")))?;
    if !is_worker_context(&context) {
        return Err(HostError::Fence(
            "FUSE worker is outside its fixed MAC domain",
        ));
    }
    Ok(())
}

fn is_worker_context(context: &[u8]) -> bool {
    // The configured policy is non-MLS. No caller-selected range, whitespace,
    // alternate domain or extra attribute is admitted by this closed role.
    context == WORKER_CONTEXT
        || (context.len() == WORKER_CONTEXT.len() + 1
            && context.starts_with(WORKER_CONTEXT)
            && context.last() == Some(&0))
}

async fn observe_running(
    systemd: &FixedFuseWorkerPid1ClientV1,
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

#[cfg(test)]
mod tests {
    use super::{WORKER_CONTEXT, is_worker_context};

    #[test]
    fn requires_exact_current_worker_domain() {
        assert!(is_worker_context(WORKER_CONTEXT));
        let mut terminated = WORKER_CONTEXT.to_vec();
        terminated.push(0);
        assert!(is_worker_context(&terminated));

        for context in [
            b"system_u:system_r:init_t".as_slice(),
            b"system_u:system_r:aos_filesystem_fuse_worker_t:s0".as_slice(),
            b"system_u:system_r:aos_filesystem_fuse_worker_t\n".as_slice(),
            b"system_u:system_r:aos_filesystem_fuse_worker_t\0\0".as_slice(),
            b"".as_slice(),
        ] {
            assert!(!is_worker_context(context));
        }
    }
}
