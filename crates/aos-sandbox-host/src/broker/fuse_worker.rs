//! Actual fixed launch after purpose-56 admission and permanent Host escrow.
//!
//! The security receiver must hold its genuine pending session cut through this
//! call and consume the original packet before entering it. The Host separately
//! verifies the current signed plan/lease and installed runtime, retains durable
//! escrow before PID1, then co-owns the actual private manager and worker pins.
//! Neither the response nor cold escrow reconstructs connected/read authority.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, PrepareHostFuseWorkerSessionResponseV1};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::fuse_worker_startup::validate_fixed_fuse_worker_launch_roles;
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_PREPARATION_PLAN_BYTES_V1, WorkerPreparationPlanV1,
};
use aos_sandbox_protocol::host_fuse_worker_session::decode_host_fuse_worker_session_request_v1;
use aos_systemd::{FixedFuseWorkerPid1ClientV1, FuseWorkerUnitNameV1};

use super::*;
use crate::fuse_worker::RetainedFuseWorkerHostLaunchV1;

pub(super) struct RetainedOriginalHostFuseWorkerV1 {
    manager: FixedFuseWorkerPid1ClientV1,
    launch: RetainedFuseWorkerHostLaunchV1,
}

/// Owns original Host-produced reply copies without issuing live-worker authority.
///
/// The actual launch remains retained in the owning serialized Host broker.
/// A caller must separately retain its pending session, Mount writer and all
/// original objects; these response bytes/descriptors cannot reconstruct that
/// custody or permit a fresh challenge before the complete copy-close barrier.
pub struct OriginalHostFuseWorkerReplyV1 {
    pub(crate) body: Vec<u8>,
    pub(crate) descriptors: [OwnedFd; 2],
}

impl<C: HostCatalog, S: HostStateStore + Sync, W: HostWorker + Sync> HostBroker<C, S, W> {
    pub(crate) async fn prepare_original_fuse_worker(
        &mut self,
        original: &AuthenticatedBrokerMethodRequestV1,
        roles: [OwnedFd; 4],
        pending_guard: &mut (dyn FnMut() -> Result<()> + Send),
    ) -> Result<OriginalHostFuseWorkerReplyV1> {
        self.ensure_healthy()?;
        pending_guard()?;
        if original.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || original.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
        {
            return Err(HostError::Fence("not an original received worker request"));
        }
        let fresh = crate::service::trusted_paired_clock_sample()?;
        let request = decode_host_fuse_worker_session_request_v1(
            original.exact_body(),
            original.peer(),
            original.peer_policy(),
            fresh.boottime_nanoseconds(),
        )?;
        self.checked_scope_runtime(request.fence())?;
        let (base, current) = self.open_scope_fence(request.fence())?;
        let admitted = self.authority.admit_fuse_worker(
            original
                .authorization()
                .ok_or(HostError::Fence("worker grant is absent"))?,
            &request,
            original.exact_body(),
            &fresh,
            &base,
        )?;
        if current.assignment() != admitted.fence.assignment()
            || current.local_lease_record() != admitted.fence.local_lease_record()
        {
            return Err(HostError::Fence("worker changed installed Host custody"));
        }
        validate_fixed_fuse_worker_launch_roles(roles.each_ref().map(|role| role.as_fd()))
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let plan_copy =
            roles[0]
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "inspect original sealed worker plan",
                    source,
                })?;
        let plan = SealedMemfdMapping::run(
            plan_copy,
            WORKER_PREPARATION_PLAN_BYTES_V1 as u64,
            WORKER_PREPARATION_PLAN_BYTES_V1 as u64,
            |bytes, _| WorkerPreparationPlanV1::decode(bytes),
        )
        .map_err(|error| HostError::Worker(error.to_string()))?
        .map_err(|_| HostError::Fence("original sealed worker plan is malformed"))?;
        if plan.worker_instance != request.worker_instance()
            || plan.kernel_boot != fresh.host_boot_id()
            || plan.mount_reservation != request.reservation_commitment()
            || plan.assignment != *request.fence().assignment_digest()
            || plan
                .digest()
                .map_err(|_| HostError::Fence("worker plan digest is malformed"))?
                != request.plan_digest()
            || request.header().deadline_boottime_nanoseconds()
                > plan.preparation_deadline_boottime_ns
            || plan.ownership_lease != *admitted.fence.local_lease_record().renewal_nonce()
            || plan.ownership_lease_expires_boottime_ns
                > admitted
                    .fence
                    .local_lease_record()
                    .fail_stop_boottime_nanoseconds()
        {
            return Err(HostError::Fence("original sealed worker plan join changed"));
        }
        let mut proposed = self.state.clone();
        proposed.retain_original_fuse_worker_launch(
            original,
            &request,
            &admitted,
            base.clone(),
            fresh.host_boot_id(),
            &self.authority,
        )?;
        self.commit_state(&proposed)?;
        pending_guard()?;

        // All failures after durable reservation leave the locator occupied.
        // Do not reconstruct launch custody or rearm from a historical row.
        let manager = FixedFuseWorkerPid1ClientV1::connect_fixed()
            .await
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let cgroup_fd = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| HostError::Worker(error.to_string()))?;
        let cgroups = CgroupV2Root::from_owned(cgroup_fd)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let name = FuseWorkerUnitNameV1::from_instance(plan.worker_instance)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        // The serialized broker excludes local commits, not filesystem drift
        // during PID1 awaits. Load the protected store on each final guard and
        // require the entire authenticated post-escrow snapshot, not absence.
        let authority = &self.authority;
        let state = &self.state;
        let store = &self.store;
        let mut guard = || {
            pending_guard()?;
            crate::state::require_current_worker_snapshot(store, state, authority)?;
            let now_base = state
                .prior_authorization(request.fence().sandbox_id())
                .ok_or(HostError::UnknownHandle)?;
            let now_fence = authority.open_fence(request.fence().sandbox_id(), now_base)?;
            if now_base != base || now_fence != current {
                return Err(HostError::Fence(
                    "installed Host fence changed before worker launch",
                ));
            }
            authority.check_before_effect(&admitted.effect, &mut || {
                crate::service::trusted_paired_clock_sample()
                    .map_err(|_| aos_sandbox_broker::BrokerAdmissionError::FenceRejected)
            })?;
            Ok(())
        };
        let launch = RetainedFuseWorkerHostLaunchV1::launch_guarded(
            &manager, &cgroups, name, roles, &mut guard,
        )
        .await?;
        self.fuse_workers.insert(
            plan.worker_instance,
            RetainedOriginalHostFuseWorkerV1 { manager, launch },
        );
        guard()?;
        let retained = self
            .fuse_workers
            .get(&plan.worker_instance)
            .ok_or(HostError::UnknownHandle)?;
        retained.launch.recheck(&retained.manager).await?;
        guard()?;
        let cgroup = FuseWorkerUnitNameV1::from_instance(plan.worker_instance)
            .map_err(|error| HostError::Worker(error.to_string()))?
            .cgroup_path();
        let body = PrepareHostFuseWorkerSessionResponseV1 {
            worker_instance_id: plan.worker_instance.to_vec(),
            preparation_plan_digest: request.plan_digest().to_vec(),
            mount_reservation_commitment: request.reservation_commitment().to_vec(),
            launch_request_commitment: request.request_commitment().to_vec(),
            kernel_boot_id: fresh.host_boot_id().to_vec(),
            host_invocation_id: retained.launch.invocation().to_vec(),
            worker_pid: retained.launch.process_identity().pid(),
            worker_cgroup: cgroup.as_str().to_owned(),
            ..Default::default()
        }
        .encode_to_vec();
        if body.len() > original.maximum_response_bytes() as usize {
            return Err(HostError::Fence("original worker reply exceeds its bound"));
        }
        aos_sandbox_protocol::host_fuse_worker_session::decode_host_fuse_worker_session_response_v1(
            &body, &request,
        )?;
        let duplicate = |fd: std::os::fd::BorrowedFd<'_>| {
            fd.try_clone_to_owned()
                .map_err(|source| HostError::Descriptor {
                    operation: "reply original worker custody",
                    source,
                })
        };
        let descriptors = [
            duplicate(retained.launch.process().as_fd())?,
            duplicate(retained.launch.cgroup())?,
        ];
        retained.launch.recheck(&retained.manager).await?;
        guard()?;
        Ok(OriginalHostFuseWorkerReplyV1 { body, descriptors })
    }
}
