//! Host-only benchmark task custody beside the original assignment owners.

use super::*;
use crate::supervision::AssignmentHostWatchdogGuard;
use crucible_linux_resource::host_services::HostServiceLease;
use crucible_linux_resource::host_supervision::HostOperationGuard;

pub(super) const WORKER_STACK: usize = 512 * 1024;

pub(super) struct WorkerService {
    registry: crate::HostOperationalRegistry,
    owner: [u8; 32],
    allocator: HostServiceAllocator,
    watchdog: Option<AssignmentHostWatchdogGuard>,
    custody: Arc<dyn Send + Sync>,
    quarantined: AtomicBool,
    released: bool,
    cancellation: crate::ExecutionCancellation,
    progress: Arc<HostOperationGuard>,
}

impl WorkerService {
    pub(super) fn admit(owner: &GuardedCampaignOwner, config: &PackagedQemuExecutorConfig) -> Self {
        let registry = owner
            .inner
            .actor
            .with_supervisor(|actor| Ok(actor.host_operational_registry()))
            .expect("original actual registry");
        let resources = HostResourceVector {
            resident_peak_bytes: 8 << 20,
            backing_peak_bytes: 1 << 20,
            // The controller census adds a finite 1 MiB metadata/scratch
            // subset beside four worker halves and the report's 2 MiB bank.
            metadata_bytes: 5 << 20,
            staging_bytes: 1 << 20,
            paging_io_slots: 1,
            cpu_slots: 4,
            task_slots: 5,
            file_descriptors: 7,
        };
        let supervisor = HostOperationSupervisor::new(
            config
                .host_operation_budgets()
                .expect("authored infrastructure roster"),
            Some(Duration::from_secs(3600)),
        )
        .expect("one original finite matrix Service cap");
        let mut identity = blake3::Hasher::new();
        identity.update(b"crucible.native-throughput-worker-service.v1\0");
        identity.update(&supervisor.cap_id());
        let service = *identity.finalize().as_bytes();
        registry
            .reserve_service_with_assignment_headroom(
                service,
                resources,
                config
                    .assignment_resources()
                    .expect("exact authored assignment"),
            )
            .expect("actual aggregate Service reservation before allocation and task creation");
        let custody = registry
            .capacity_custody()
            .expect("same original charged actor");
        let allocator = HostServiceAllocator::new(4, 7, 7 << 20)
            .expect("explicit worker subset leaves the watchdog's envelope outside");
        let cancellation = crate::ExecutionCancellation::default();
        let progress = Arc::new(
            supervisor
                .begin_work(
                    HostOperationClass::Preparation,
                    u64::try_from(TARGET_DIVISORS.len() * PARALLEL.len() * REPEATS)
                        .expect("fixed finite row inventory"),
                )
                .expect("one original matrix operation before host work"),
        );
        let watchdog = AssignmentHostWatchdogGuard::start_service(supervisor, cancellation.clone())
            .expect("original admitted Service watcher and bounded stack");
        Self {
            registry,
            owner: service,
            allocator,
            watchdog: Some(watchdog),
            custody,
            quarantined: AtomicBool::new(false),
            released: false,
            cancellation,
            progress,
        }
    }

    pub(super) fn reserve_worker(&self) -> HostServiceLease {
        self.progress
            .wait_slice()
            .expect("original Service guard before every task spawn");
        self.allocator
            .reserve_resources(1, 1, 1 << 20)
            .expect("actual task, finite stack/TLS and metadata permit before spawn")
    }

    pub(super) fn reserve_report(&self) -> HostServiceLease {
        self.allocator
            .reserve_resources(0, 1, 2 << 20)
            .expect("report, pinned input and sampling storage loan before allocation")
    }

    pub(super) fn cancellation(&self) -> crate::ExecutionCancellation {
        self.cancellation.clone()
    }

    pub(super) fn reserve_census(&self) -> Result<HostServiceLease, HostOperationalError> {
        self.progress
            .wait_slice()
            .map_err(|_| HostOperationalError::Unavailable)?;
        self.allocator
            .reserve_resources(
                0,
                resource_census::DESCRIPTORS,
                resource_census::SCRATCH_BYTES,
            )
            .map_err(|_| HostOperationalError::Unavailable)
    }

    pub(super) fn supervisor(&self) -> HostOperationSupervisor {
        self.watchdog
            .as_ref()
            .expect("original matrix watcher")
            .state
            .supervisor()
            .clone()
    }

    pub(super) fn completed_row(&self, completed: u64) {
        self.progress
            .progress(completed)
            .expect("progress only after a complete measured row and real worker joins");
    }

    pub(super) fn quarantine(&self) {
        self.quarantined.store(true, Ordering::Release);
    }

    pub(super) fn release_after_joined_workers(mut self) {
        if self.quarantined.load(Ordering::Acquire) {
            return;
        }
        self.progress
            .complete()
            .expect("every row and report finished under the original cap");
        self.watchdog
            .as_mut()
            .expect("original matrix watcher")
            .stop();
        self.registry
            .release_service_after_cleanup(self.owner)
            .expect("all scoped worker handles joined before Service discharge");
        self.released = true;
    }
}

impl Drop for WorkerService {
    fn drop(&mut self) {
        if !self.released {
            // Zero native node records do not prove these host workers joined.
            // Retain the real actor, original cap/watcher and allocator if an
            // assertion, panic or unknown task cleanup skips explicit release.
            std::mem::forget((
                self.custody.clone(),
                self.watchdog.take(),
                self.allocator.clone(),
                self.progress.clone(),
            ));
        }
    }
}
