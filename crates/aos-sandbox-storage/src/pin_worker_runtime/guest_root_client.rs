//! Connects the method31 publisher to the sole retained descriptor-worker engine.
//!
//! Startup health and pre-admission quiescence preserve their existing
//! observation-only behavior. A mutation has no ordinary exchange entrance:
//! its actual same-F State loan selects the closed method31 physical kind.

use super::*;
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;

/// Invokes only the fixed root-owned one-shot publisher and retains its cgroup to exit.
pub(crate) struct SystemdGuestRootPublisherClientV1 {
    executor: SystemdWorkspacePinExecutor,
}

impl SystemdGuestRootPublisherClientV1 {
    pub(crate) fn new(socket_path: PathBuf, cgroup_root: CgroupV2Root) -> Result<Self, ZfsWorkerError> {
        if socket_path != Path::new("/run/aos/sandbox-guest-root-publisher/control.sock") {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(Self { executor: SystemdWorkspacePinExecutor::new_for_role(
            socket_path, cgroup_root, WorkspacePinServiceRole::GuestRootPublication31,
        )? })
    }

    pub(crate) fn publish_receiving_v2(
        &mut self,
        request: &[u8],
        attempt: &crate::guest_root_attempt::GuestRootPublicationAttemptV2,
        effect_deadline: u64,
        stage: &mut crate::process::receiving_stage::StoragePhysicalWorkerStageV1<'_, '_, '_>,
    ) -> Result<GuestRootPublicationProofV1, ZfsWorkerError> {
        if crate::guest_root_worker::decode_request(request)?.effect_operation() != attempt.effect_operation {
            return Err(ZfsWorkerError::Authority);
        }
        self.executor.exchange_guest_root_receiving_v2(request, attempt, effect_deadline, stage)
    }

    pub(crate) fn health_worker_receiving_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        SystemdWorkspacePinExecutor::guest_root_startup_health_demand_v2()
    }

    pub(crate) fn probe_receiving_entered_v2(
        &mut self, deadline: u64, demand: aos_sandbox_core::ResourceVector,
        flight: aos_sandbox::StoragePhysicalWorkerLoanV1<'_, '_>,
    ) -> Result<(), ZfsWorkerError> {
        self.executor.exchange_guest_root_startup_health_entered_v2(deadline, demand, flight)
    }

    /// Uses the sole whole-roster observation-only quiescence engine.
    pub(crate) fn recover_quiescence(&mut self) -> Result<(), ZfsWorkerError> {
        self.executor.recover_quiescence()
    }

    /// Proves the installed fixed service can start with its protected inputs.
    ///
    /// The health packet contains no authority and the worker returns before
    /// opening a workspace slot or attempting any filesystem mutation.
    pub(crate) fn probe(&mut self) -> Result<(), ZfsWorkerError> {
        if self.executor.fail_stopped {
            return Err(ZfsWorkerError::Authority);
        }
        let mut socket = DescriptorSubjectSocket::connect(&self.executor.socket_path)?;
        verify_systemd_peer(socket.peer(), &self.executor.systemd_manager_cgroup)?;
        // Template verification scans the complete pinned package before the
        // worker sends READY; it is bounded separately from packet transfer.
        let ready_deadline = boottime_now_nanoseconds()?
            .checked_add(Duration::from_secs(60).as_nanos() as u64)
            .ok_or(ZfsWorkerError::Authority)?;
        let ready = receive_packet_before(&mut socket, 520, ready_deadline)?;
        if !ready.descriptors().is_empty() {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        let worker_path = decode_ready(ready.payload(), WorkspacePinServiceRole::GuestRootPublication31)?;
        let worker_cgroup = self.executor.worker_parent_cgroup.resolve_descendant(Path::new(
            worker_path
                .strip_prefix("aos.slice/aos-control.slice/")
                .ok_or(ZfsWorkerError::PeerMismatch)?,
        ))?;
        verify_exact_worker_subject(ready.subject(), &worker_cgroup)?;
        let population = worker_cgroup.population_monitor()?;
        let deadline = transfer_deadline()?;

        let exchange = (|| {
            send_packet_before(&mut socket, crate::guest_root_worker::HEALTH_REQUEST_MAGIC, deadline)?;
            let response = receive_packet_before(&mut socket, crate::guest_root_worker::HEALTH_RESULT_MAGIC.len(), deadline)?;
            verify_same_live_subject(ready.subject(), response.subject())?;
            verify_exact_worker_subject(response.subject(), &worker_cgroup)?;
            if !response.descriptors().is_empty() || response.payload() != crate::guest_root_worker::HEALTH_RESULT_MAGIC {
                return Err(ZfsWorkerError::PeerMismatch);
            }
            send_packet_before(&mut socket, crate::guest_root_worker::ACK_MAGIC, deadline)?;
            Ok(())
        })();
        self.finish_exchange(exchange, ready.subject(), &worker_cgroup, &population)
    }

    fn finish_exchange<T>(
        &mut self,
        exchange: Result<T, ZfsWorkerError>,
        subject: &KernelAuthorizedRecordSubject,
        worker_cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<T, ZfsWorkerError> {
        match exchange {
            Ok(proof) => {
                if let Err(error) =
                    wait_for_worker_quiescence(subject, population, Duration::from_secs(1))
                {
                    if quiesce_worker(subject, worker_cgroup, population).is_err() {
                        self.executor.fail_stopped = true;
                    }
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "guest-root publisher did not exit cleanly: {error}"
                    )));
                }
                Ok(proof)
            }
            Err(error) => {
                if let Err(cancellation) = quiesce_worker(subject, worker_cgroup, population) {
                    self.executor.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "guest-root publisher cancellation failed after {error}: {cancellation}"
                    )));
                }
                Err(error)
            }
        }
    }


}


/// Keeps fixed-root and child resolution prefixes on the actual State31 owner.
pub(crate) struct GuestRootPublisherOpenOriginalV2 {
    root_native: aos_sandbox_linux::cgroup::CgroupRootOriginalV2,
    root: Option<Result<CgroupV2Root, aos_sandbox::normal_root::StorageCgroupRootErrorV3>>,
    manager_native: aos_sandbox_linux::cgroup::CgroupChildOriginalV2,
    manager: Option<Result<(), aos_sandbox_linux::Error>>,
    manager_anchor: Option<RetainedCgroupAnchor>,
    parent_native: aos_sandbox_linux::cgroup::CgroupChildOriginalV2,
    parent: Option<Result<(), aos_sandbox_linux::Error>>,
    parent_anchor: Option<RetainedCgroupAnchor>,
    entered: bool,
    taken: bool,
    closed: bool,
}

impl GuestRootPublisherOpenOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            root_native: aos_sandbox_linux::cgroup::CgroupRootOriginalV2::new(), root: None,
            manager_native: aos_sandbox_linux::cgroup::CgroupChildOriginalV2::new(), manager: None,
            manager_anchor: None,
            parent_native: aos_sandbox_linux::cgroup::CgroupChildOriginalV2::new(), parent: None,
            parent_anchor: None, entered: false, taken: false, closed: false,
        }
    }

    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let parent = aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate.worker_parent_relative_v1();
        let root = aos_sandbox_linux::cgroup::CgroupRootOriginalV2::receiving_obligations_v2()?;
        let manager = aos_sandbox_linux::cgroup::CgroupChildOriginalV2::receiving_obligations_v2(SYSTEMD_MANAGER_CGROUP.len())?;
        let parent = aos_sandbox_linux::cgroup::CgroupChildOriginalV2::receiving_obligations_v2(parent.len())?;
        let bytes = root.0.checked_add(manager.0)?.checked_add(parent.0)?
            .checked_add(3 * std::mem::size_of::<Self>())?
            .checked_add(3 * "/run/aos/sandbox-guest-root-publisher/control.sock".len())?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(root.1.checked_add(manager.1)?.checked_add(parent.1)?).ok()?)
            .with(D::MetadataEntries, u64::try_from(root.2.checked_add(manager.2)?.checked_add(parent.2)?).ok()?))
    }

    pub(crate) fn open_once_v2(&mut self) -> Result<SystemdGuestRootPublisherClientV1, ZfsWorkerError> {
        if self.entered {
            self.closed = true;
            return Err(ZfsWorkerError::Authority);
        }
        self.entered = true;
        self.root = Some(aos_sandbox::normal_root::open_storage_cgroup_root_retaining_v3(&mut self.root_native));
        let Some(Ok(root)) = self.root.as_ref() else { return Err(ZfsWorkerError::Authority); };
        self.manager = Some(self.manager_native.resolve_once(root, Path::new(SYSTEMD_MANAGER_CGROUP)));
        if !matches!(self.manager, Some(Ok(()))) { return Err(ZfsWorkerError::Authority); }
        self.manager_anchor = self.manager_native.take_completed_once();
        let parent = aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate.worker_parent_relative_v1();
        self.parent = Some(self.parent_native.resolve_once(root, Path::new(parent)));
        if !matches!(self.parent, Some(Ok(()))) { return Err(ZfsWorkerError::Authority); }
        self.parent_anchor = self.parent_native.take_completed_once();
        let (manager, parent) = match (self.manager_anchor.take(), self.parent_anchor.take()) {
            (Some(manager), Some(parent)) => (manager, parent),
            (manager, parent) => {
                self.manager_anchor = manager;
                self.parent_anchor = parent;
                return Err(ZfsWorkerError::Authority);
            }
        };
        self.taken = true;
        Ok(SystemdGuestRootPublisherClientV1 {
            executor: SystemdWorkspacePinExecutor {
                socket_path: PathBuf::from("/run/aos/sandbox-guest-root-publisher/control.sock"),
                systemd_manager_cgroup: manager, worker_parent_cgroup: parent,
                role: WorkspacePinServiceRole::GuestRootPublication31,
                fail_stopped: false, catalog_observation: None,
            },
        })
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root_native.failure().map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.root.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.manager_native.failure().map(|cause| cause as _))
            .or_else(|| self.parent_native.failure().map(|cause| cause as _))
            .or_else(|| (self.entered && (!self.taken || self.closed)).then_some(&ZfsWorkerError::Authority as &dyn std::error::Error))
    }
}
