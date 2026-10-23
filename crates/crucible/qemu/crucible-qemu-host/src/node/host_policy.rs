//! Retains RAM cleanup custody and attaches operational node supervision.

use super::*;

impl QemuNode {
    pub(super) fn finish_host_ram_cleanup(&mut self) -> Result<(), QemuNodeError> {
        let child = &mut self.child;
        let runtime = &mut self.host_io_runtime;
        #[cfg(target_os = "linux")]
        let stage = &mut self.hot_fork_ram_stage;
        #[cfg(target_os = "linux")]
        let continuation = &mut self.hot_fork_ram_continuation;
        self.child_shutdown.finish_ram(|original, history| {
            let mut returned = true;
            #[cfg(target_os = "linux")]
            {
                if let Some(stage) = stage
                    && let Err(first) = stage.finish_source()
                {
                    history.retain_stage(first);
                    returned = false;
                }
                if let QemuNodeProcessControl::Direct(child) = child {
                    drop(child.ram_source_start.take());
                    returned &= history.source(1, &mut child.ram_source, original);
                }
                if let Some(ram) = continuation {
                    returned &= ram.finish(original, history);
                }
            }
            if returned {
                let (closed, status) =
                    runtime.retire_host_ram_after_cleanup(original, &mut history.retirement[0]);
                history.controller(0, status);
                returned &= closed;
            }
            returned
        })
    }

    /// Observes whole-leaf closure separately from permanent cleanup history.
    ///
    /// This factual observation grants neither a new operation nor a generation.
    #[must_use]
    pub fn cleanup_physically_returned(&self) -> bool {
        self.child.reaped() && self.child_shutdown.physically_returned()
    }

    /// Attaches one operational owner before a reconstructed node is released.
    ///
    /// Both QMP and host I/O retain the same owner; no guest or modeled state is
    /// changed. Native paging admission remains a separate readiness obligation.
    ///
    /// # Errors
    /// Returns a channel error if either existing live transport cannot retain
    /// the independently admitted operational supervision owner.
    pub fn attach_host_operation_supervisor(
        &mut self,
        supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Result<(), QemuNodeChannelError> {
        self.channels
            .qmp_machine_control
            .set_host_operation_supervisor(supervisor.clone())?;
        self.host_io_runtime
            .set_host_operation_supervisor(supervisor)
            .map_err(|source| {
                QemuNodeChannelError::new("attach host operation supervisor", source.to_string())
            })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
    use crate::ram_source::{QemuRamBacking, QemuRamSourceError, QemuRamSourceService};
    use crucible_engine::{BackendError, SchedulerError, SchedulerOperationalFailureClass};
    use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceError};
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor, HostSupervisionError,
    };
    use crucible_qemu_protocol::ram_page::{RamPageBinding, RamPageRequest};
    use std::error::Error;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    // Real socket/worker cleanup, without a QEMU process or native RAM authority.
    struct SourceFixture {
        retained: Option<QemuRamSourceService>,
        peer: UnixStream,
        backing: Arc<ImmutableBacking>,
        binding: RamPageBinding,
        services: HostServiceAllocator,
        supervisor: HostOperationSupervisor,
        cleanup: crucible_host_resources::host_supervision::HostOperationGuard,
        history: super::super::ram_cleanup::RamCleanup,
    }

    impl SourceFixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let backing = Arc::new(ImmutableBacking::new(2)?);
            let binding = RamPageBinding {
                session: [1; 16],
                owner_incarnation: [2; 16],
                source_generation: 1,
                root_digest: *backing.root_record().digest().as_bytes(),
            };

            let supervisor = HostOperationSupervisor::new(
                HostOperationBudgets::default(),
                Some(Duration::from_secs(5)),
            )?;
            let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;

            let (server, peer) = UnixStream::pair()?;
            let service = QemuRamSourceService::start_component(
                server,
                backing.clone(),
                binding,
                supervisor.clone(),
                services.clone(),
                None,
            )?;

            let cleanup = supervisor.begin(HostOperationClass::Cleanup)?;
            Ok(Self {
                retained: Some(service),
                peer,
                backing,
                binding,
                services,
                supervisor,
                cleanup,
                history: super::super::ram_cleanup::RamCleanup::new(),
            })
        }

        fn refuse_an_authenticated_page(&mut self) -> Result<(), Box<dyn Error>> {
            self.backing.corrupt_reads.store(true, Ordering::Release);
            self.peer.write_all(
                &RamPageRequest {
                    binding: self.binding,
                    sequence: 1,
                    region_ordinal: 0,
                    page_index: 0,
                }
                .encode()?,
            )?;

            let observation = self.supervisor.begin(HostOperationClass::Preparation)?;
            loop {
                match self.retained.as_ref().unwrap().check_health() {
                    Err(QemuRamSourceError::WorkerFailed(_)) => break,
                    Err(source) => return Err(source.into()),
                    Ok(()) => {
                        std::thread::sleep(observation.wait_slice()?.min(Duration::from_millis(1)))
                    }
                }
            }

            observation.complete()?;
            Ok(())
        }

        fn close(&mut self) -> bool {
            self.history.source(
                1,
                &mut self.retained,
                Some(crate::ram_control::RamCleanupOriginal::direct(
                    &self.cleanup,
                    &self.supervisor,
                )),
            )
        }

        fn task_is_retained(&self) -> bool {
            matches!(
                self.services.reserve_resources(1, 0, 0),
                Err(HostServiceError::CapacityExhausted)
            )
        }
    }

    #[test]
    fn same_cleanup_keeps_worker_cause_and_service_until_physical_return_is_reported()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = SourceFixture::new()?;
        fixture.refuse_an_authenticated_page()?;
        assert!(!fixture.close());
        let error = fixture
            .history
            .failure()
            .ok_or("raw worker cause missing")?;
        let observed = fixture
            .retained
            .as_ref()
            .unwrap()
            .check_health()
            .unwrap_err();
        let QemuRamSourceError::WorkerFailed(worker) = observed else {
            panic!("the retained service must expose its original worker failure");
        };
        assert!(matches!(worker.as_ref(), QemuRamSourceError::Proof(_)));
        let QemuNodeError::RamCleanup { sources, .. } = &error else {
            panic!("cleanup must preserve the typed source failure");
        };
        assert_eq!(
            sources[1]
                .as_ref()
                .and_then(|history| history.worker.as_ref()),
            Some(&worker)
        );
        assert!(fixture.task_is_retained());

        // The actual joined body leaves its slot only after the same journal
        // delivered failure. The scheduler still owns that worker's same cause.
        assert!(fixture.close());
        assert!(fixture.retained.is_none());
        let scheduler = SchedulerError::from(BackendError::from(error));
        assert_eq!(
            scheduler.operational_failure_class(),
            Some(SchedulerOperationalFailureClass::Terminal)
        );
        drop(worker);
        assert!(fixture.task_is_retained());
        drop(scheduler);
        drop(fixture.history);
        assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        Ok(())
    }

    #[test]
    fn healthy_source_cleanup_removes_the_service_and_is_idempotent() -> Result<(), Box<dyn Error>>
    {
        let mut fixture = SourceFixture::new()?;
        assert!(fixture.task_is_retained());

        assert!(fixture.close());
        assert!(fixture.close());

        assert!(fixture.retained.is_none());
        assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        Ok(())
    }

    #[test]
    fn source_cleanup_uses_same_saved_guard_when_new_cleanup_admission_is_full()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = SourceFixture::new()?;
        let original_id = fixture.cleanup.status()?.operation_id;
        let mut guards = Vec::new();
        loop {
            match fixture.supervisor.begin(HostOperationClass::Cleanup) {
                Ok(guard) => guards.push(guard),
                Err(HostSupervisionError::CapacityExhausted) => break,
                Err(source) => return Err(source.into()),
            }
        }
        assert!(fixture.task_is_retained());
        assert!(matches!(
            fixture.supervisor.begin(HostOperationClass::Cleanup),
            Err(HostSupervisionError::CapacityExhausted)
        ));

        assert!(fixture.close());

        assert_eq!(fixture.cleanup.status()?.operation_id, original_id);
        assert!(fixture.retained.is_none());
        assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());
        drop(guards);
        Ok(())
    }
}
